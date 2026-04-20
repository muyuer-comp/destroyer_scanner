# Destroyer Scanner

Destroyer 恶意脚本查杀引擎 - 专注于检测和识别恶意脚本的危险行为，包括杀毒软件杀手、勒索软件相关行为等。

## 功能特性

- **多威胁类型检测**：支持检测 AVkiller、Ransom、KillWin、UserManag 等多种威胁类型
- **全面的特征库**：包含大量危险行为特征，覆盖多种恶意脚本操作
- **快速扫描**：采用高效的正则表达式匹配，快速识别恶意特征
- **详细的威胁分类**：根据行为特征对威胁进行精确分类
- **易于集成**：简洁的 API 设计，方便集成到其他项目中

## 项目结构

```
.
├── destroyer_scanner.py    # 核心扫描引擎
└── scan_destroyer.py       # 调用工具（非必需）
```

## 威胁类型

### 1. AVkiller
- **检测条件**：检测到结束杀毒软件进程的行为
- **包含的杀毒软件**：
  - 国外：Kaspersky、Avira、Bitdefender、Malwarebytes、Windows Defender、McAfee、Norton
  - 国内：360、QQ电脑管家、火绒、瑞星、江民、金山毒霸、猎豹终端安全、华为终端防护

### 2. Ransom
- **检测条件**：检测到2个或以上勒索相关行为
- **包含的行为**：
  - 创建公私钥
  - 添加文件后缀
  - 弱密码爆破
  - 禁用安全服务
  - 隐藏文件

### 3. KillWin
- **检测条件**：检测到系统破坏行为
- **包含的行为**：
  - 删除系统文件
  - 禁用系统服务
  - 破坏引导
  - 删除注册表
  - 禁用系统功能
  - 格式化系统分区

### 4. UserManag
- **检测条件**：检测到用户管理相关行为
- **包含的行为**：
  - 添加用户
  - 删除用户
  - 设置用户密码
  - 禁用管理员账户
  - 启用Guest账户

## 快速开始

### 安装依赖

本项目使用 Python 标准库，无需额外安装依赖。

### 使用方法

#### 1. 命令行扫描

**扫描单个文件**：
```bash
python scan_destroyer.py C:\path\to\file.bat
```

**扫描目录**：
```bash
python scan_destroyer.py D:\Downloads
```

**静默模式**：
```bash
python scan_destroyer.py E:\Scripts --quiet
```

**查看帮助**：
```bash
python scan_destroyer.py --help
```

#### 2. 代码集成

```python
from destroyer_scanner import DestroyerScanner

# 初始化扫描器
scanner = DestroyerScanner(quiet=False)

# 扫描单个文件
result = scanner.scan_file(r"C:\path\to\file.bat")
if result:
    print(f"检测到威胁: {result}")
else:
    print("未检测到威胁")

# 扫描目录
threats = scanner.scan_directory(r"D:\Downloads")
for file_path, threat_type in threats:
    print(f"{threat_type} - {file_path}")
```

## API 参考

### DestroyerScanner

#### 构造函数

```python
DestroyerScanner(quiet=False)
```

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| quiet | bool | False | 静默模式，减少输出信息 |

#### 方法

- `scan_file(file_path)` - 扫描单个文件，返回威胁类型或 None
- `scan_directory(directory)` - 扫描目录，返回威胁列表

## 支持的文件格式

- `.bat`、`.cmd` - 批处理文件
- `.vb`、`.vbs`、`.vbe` - VBScript 文件
- `.ps1` - PowerShell 脚本
- `.txt` - 文本文件
- 其他文本格式的脚本文件

## 技术原理

1. **特征提取**：使用正则表达式匹配恶意行为特征
2. **行为分析**：根据匹配到的特征判断威胁类型
3. **威胁分类**：根据预设规则对威胁进行分类
4. **结果输出**：返回详细的威胁类型信息

## 注意事项

- 扫描结果仅供参考，不能作为唯一的安全判断依据
- 对于加密或压缩的文件，可能无法正确检测
- 建议结合其他安全工具使用，提高检测准确率

## License

MIT License
