# FreeBlade 存档工具

用于解密、修改并重新加密 FreeBlade 的 `savedata.dat` 存档。

支持查看存档信息、校验外层 MD5、更新内部 Hash，并参照原始存档恢复加密格式。目前仅适用于脚本已支持的存档格式。

## 安装

需要 Python 3，安装依赖：

```bash
python -m pip install pycryptodome
```

## 使用

将脚本和自己的 `savedata.dat` 放在同一目录，在该目录打开终端。**修改前请备份原始存档。**

### 查看信息

```bash
python FreeBladeSaveFileEditor.py info savedata.dat
```

显示存档头、版本、MD5 校验模式和内部 Hash 是否匹配。无法识别格式时会报错。

### 解密

```bash
python FreeBladeSaveFileEditor.py decrypt savedata.dat savedata.txt
```

用文本编辑器修改生成的 `savedata.txt`，保留原有键名、类型前缀和行顺序，保存为 UTF-8。

### 加密

```bash
python FreeBladeSaveFileEditor.py encrypt savedata.txt savedata_new.dat --reference savedata.dat
```

加密时会自动重算内部 Hash 和外层 MD5。`--reference` 必须指向可正常识别的原始存档，用于获取存档头、IV 和校验模式。

如需单独生成更新 Hash 后的文本：

```bash
python FreeBladeSaveFileEditor.py rehash-text savedata.txt savedata_fixed.txt
```

默认 DES 密钥文本为 `11111111`。自定义密钥需为 8 个 ASCII 字符，参数放在子命令前：

```bash
python FreeBladeSaveFileEditor.py --key 11111111 info savedata.dat
```

## Windows 快捷脚本

将批处理文件与 Python 脚本、存档放在同一目录：

- `decrypt.bat`：将 `savedata.dat` 解密为 `savedata.txt`。
- `encrypt.bat`：读取修改后的 `savedata.txt`，生成 `savedata_fixed.txt` 和 `savedata_new.dat`，以 `savedata.dat` 为参考。

重复运行会覆盖对应的输出文件。

