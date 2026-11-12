#!/usr/bin/env python3
"""
Freeblade savedata.dat tool (generic for the savedata family analyzed in this chat)

What this script does:
- Auto-detects the known savedata.dat header variant(s)
- Decrypts DES-CBC payloads using the default key text "11111111"
- Verifies the outer MD5 using the correct mode for the detected file
- Recalculates the inner text Hash field
- Re-encrypts using the same variant as a reference save

Scope:
- Intended for the Freeblade savedata.dat format family analyzed from the
  files in this conversation.
- It is not a universal tool for arbitrary games or unknown future formats.
"""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from Crypto.Cipher import DES

DEFAULT_KEY_TEXT = "11111111"
NON_HASHED_KEYS = {"Hash", "DateTimeStamp", "DateTimeStampCloud"}


@dataclass
class HeaderVariant:
    name: str
    header_size: int
    magic: bytes
    version: bytes
    save_version: int
    iv: bytes
    pad_byte_count: int
    md5_hash: bytes
    parser_name: str
    md5_mode: str  # "unpadded" or "padded"


# ---------------------------------------------------------------------------
# Header parsers
# ---------------------------------------------------------------------------

def _parse_variant_savever16(data: bytes) -> HeaderVariant:
    # Verified on the user's saves.
    header_size = 35
    if len(data) < header_size:
        raise ValueError("file too small for savever16 header")
    return HeaderVariant(
        name="savever16",
        header_size=header_size,
        magic=data[0:5],
        version=data[5:8],
        save_version=int.from_bytes(data[8:10], "little"),
        iv=data[10:18],
        pad_byte_count=data[18],
        md5_hash=data[19:35],
        parser_name="savever16",
        md5_mode="",
    )


def _parse_variant_savever8_origin8(data: bytes) -> HeaderVariant:
    # Legacy guess retained as fallback/autodetect option.
    header_size = 35
    if len(data) < header_size:
        raise ValueError("file too small for savever8_origin8 header")
    return HeaderVariant(
        name="savever8_origin8",
        header_size=header_size,
        magic=data[0:5],
        version=data[5:8],
        save_version=data[8],
        iv=data[10:18],
        pad_byte_count=data[18],
        md5_hash=data[19:35],
        parser_name="savever8_origin8",
        md5_mode="",
    )


HEADER_PARSERS: Sequence[Callable[[bytes], HeaderVariant]] = (
    _parse_variant_savever16,
    _parse_variant_savever8_origin8,
)


# ---------------------------------------------------------------------------
# Text/hash helpers
# ---------------------------------------------------------------------------

def detect_newline_style(raw: bytes) -> Tuple[str, bool]:
    has_trailing_newline = raw.endswith(b"\r\n") or raw.endswith(b"\n")
    if b"\r\n" in raw:
        return "\r\n", has_trailing_newline
    return "\n", has_trailing_newline


def decode_text_bytes(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8")



def calc_internal_hash_from_text(text: str) -> str:
    sha1 = hashlib.sha1()
    for raw_line in text.splitlines():
        if not raw_line or "=" not in raw_line or ":" not in raw_line:
            continue
        key, rest = raw_line.split("=", 1)
        if key in NON_HASHED_KEYS:
            continue
        _type_prefix, value = rest.split(":", 1)
        if value == "":
            continue
        sha1.update(value.encode("ascii"))
    sha1.update(b"Hash")
    return sha1.hexdigest().upper()



def replace_internal_hash_preserve_newlines(raw: bytes) -> bytes:
    newline, had_final_newline = detect_newline_style(raw)
    text = decode_text_bytes(raw)
    new_hash = calc_internal_hash_from_text(text)

    lines = text.splitlines()
    replaced = False
    out_lines: List[str] = []
    for line in lines:
        if line.startswith("Hash=S:"):
            out_lines.append(f"Hash=S:{new_hash}")
            replaced = True
        else:
            out_lines.append(line)
    if not replaced:
        out_lines.append(f"Hash=S:{new_hash}")

    out_text = newline.join(out_lines)
    if had_final_newline:
        out_text += newline
    return out_text.encode("utf-8")



def _extract_hash_from_text(text: str) -> Optional[str]:
    for line in text.splitlines():
        if line.startswith("Hash=S:"):
            return line[7:]
    return None


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _decrypt_candidate(data: bytes, header: HeaderVariant, key: bytes) -> Tuple[bytes, bytes]:
    enc = data[header.header_size :]
    if len(enc) % 8 != 0:
        raise ValueError("encrypted payload length is not a multiple of 8")
    cipher = DES.new(key, DES.MODE_CBC, header.iv)
    padded_plain = cipher.decrypt(enc)
    if header.pad_byte_count > len(padded_plain):
        raise ValueError("invalid pad byte count")
    if header.pad_byte_count:
        tail = padded_plain[-header.pad_byte_count :]
        if tail != b"\x00" * header.pad_byte_count:
            raise ValueError("pad bytes are not zero-filled")
        plain = padded_plain[:-header.pad_byte_count]
    else:
        plain = padded_plain
    return padded_plain, plain



def _is_plausible_plaintext(plain: bytes) -> bool:
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        return False
    head = text[:128]
    if "=" not in head or "\n" not in text[:256]:
        return False
    # Most known saves begin with ABVars.
    if text.startswith("ABVars."):
        return True
    # Fallback heuristic.
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in plain[:512])
    return printable >= min(len(plain[:512]), 450)



def autodetect_variant(data: bytes, key: bytes) -> Tuple[HeaderVariant, bytes, bytes]:
    errors: List[str] = []

    for parser in HEADER_PARSERS:
        try:
            header = parser(data)
            padded_plain, plain = _decrypt_candidate(data, header, key)
        except Exception as exc:
            errors.append(f"{parser.__name__}: {exc}")
            continue

        md5_unpadded = hashlib.md5(plain).digest()
        md5_padded = hashlib.md5(padded_plain).digest()

        if md5_unpadded == header.md5_hash and _is_plausible_plaintext(plain):
            header.md5_mode = "unpadded"
            return header, padded_plain, plain
        if md5_padded == header.md5_hash and _is_plausible_plaintext(plain):
            header.md5_mode = "padded"
            return header, padded_plain, plain

        errors.append(
            f"{parser.__name__}: md5 mismatch (header={header.md5_hash.hex()} unpadded={md5_unpadded.hex()} padded={md5_padded.hex()})"
        )

    raise ValueError("No known header variant matched. Tried: " + " | ".join(errors))



def encrypt_plaintext_bytes(plain_raw: bytes, reference_header: HeaderVariant, key: bytes) -> bytes:
    fixed_plain = replace_internal_hash_preserve_newlines(plain_raw)
    pad = (-len(fixed_plain)) % 8
    padded_plain = fixed_plain + (b"\x00" * pad)

    if reference_header.md5_mode == "unpadded":
        md5_hash = hashlib.md5(fixed_plain).digest()
    elif reference_header.md5_mode == "padded":
        md5_hash = hashlib.md5(padded_plain).digest()
    else:
        raise ValueError("reference header md5_mode is unknown; use a valid reference save")

    cipher = DES.new(key, DES.MODE_CBC, reference_header.iv)
    enc = cipher.encrypt(padded_plain)

    if reference_header.parser_name == "savever16":
        header_bytes = (
            reference_header.magic
            + reference_header.version
            + int(reference_header.save_version).to_bytes(2, "little")
            + reference_header.iv
            + bytes([pad])
            + md5_hash
        )
    elif reference_header.parser_name == "savever8_origin8":
        # Keep origin byte as zero for the legacy fallback parser.
        header_bytes = (
            reference_header.magic
            + reference_header.version
            + bytes([reference_header.save_version & 0xFF])
            + b"\x00"
            + reference_header.iv
            + bytes([pad])
            + md5_hash
        )
    else:
        raise ValueError(f"Unknown parser_name={reference_header.parser_name}")

    return header_bytes + enc


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_info(args) -> int:
    data = Path(args.input).read_bytes()
    header, padded_plain, plain = autodetect_variant(data, key=args.key.encode("ascii"))
    text = plain.decode("utf-8", errors="replace")
    current_hash = _extract_hash_from_text(text)
    calc_hash = calc_internal_hash_from_text(text)

    print(f"variant={header.name}")
    print(f"header_size={header.header_size}")
    print(f"file_size={len(data)}")
    print(f"magic={header.magic.hex()}")
    print(f"version={header.version.hex()}")
    print(f"save_version={header.save_version}")
    print(f"iv={header.iv.hex()}")
    print(f"pad_byte_count={header.pad_byte_count}")
    print(f"header_md5={header.md5_hash.hex()}")
    print(f"md5_mode={header.md5_mode}")
    print(f"calc_md5_unpadded={hashlib.md5(plain).hexdigest()}")
    print(f"calc_md5_padded={hashlib.md5(padded_plain).hexdigest()}")
    print(f"internal_hash_in_text={current_hash}")
    print(f"internal_hash_calc={calc_hash}")
    print(f"internal_hash_match={current_hash == calc_hash}")
    return 0


def cmd_decrypt(args) -> int:
    data = Path(args.input).read_bytes()
    _header, _padded_plain, plain = autodetect_variant(data, key=args.key.encode("ascii"))
    Path(args.output).write_bytes(plain)
    print(f"Decrypted to {args.output}")
    return 0


def cmd_rehash_text(args) -> int:
    raw = Path(args.input).read_bytes()
    fixed = replace_internal_hash_preserve_newlines(raw)
    Path(args.output).write_bytes(fixed)
    print(f"Rehashed text written to {args.output}")
    return 0


def cmd_encrypt(args) -> int:
    plain_raw = Path(args.input).read_bytes()
    ref_data = Path(args.reference).read_bytes()
    ref_header, _padded_plain, _plain = autodetect_variant(ref_data, key=args.key.encode("ascii"))
    out = encrypt_plaintext_bytes(plain_raw, ref_header, key=args.key.encode("ascii"))
    Path(args.output).write_bytes(out)
    print(f"Encrypted to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default=DEFAULT_KEY_TEXT, help="ASCII DES key text; default: 11111111")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="Show detected format and verify checksums")
    p.add_argument("input")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("decrypt", help="Decrypt savedata.dat to plain text")
    p.add_argument("input")
    p.add_argument("output")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("rehash-text", help="Recalculate inner Hash=S:... in a plain text save")
    p.add_argument("input")
    p.add_argument("output")
    p.set_defaults(func=cmd_rehash_text)

    p = sub.add_parser("encrypt", help="Encrypt plain text save back to savedata.dat")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--reference", required=True, help="Reference savedata.dat used to autodetect format and IV")
    p.set_defaults(func=cmd_encrypt)

    return ap


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
