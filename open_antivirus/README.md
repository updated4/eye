# OpenAntivirus - 开源杀毒软件

一个用 Python 编写的开源杀毒软件核心引擎，提供基础的病毒检测和防护功能。

## 功能特性

- ✅ **特征码扫描**: 基于已知病毒哈希值的快速检测
- ✅ **启发式扫描**: 检测可疑行为和模式
- ✅ **文件完整性校验**: SHA256 哈希计算
- ✅ **隔离区管理**: 安全隔离受感染文件
- ✅ **报告生成**: JSON 格式的详细扫描报告
- ✅ **命令行界面**: 简单易用的 CLI 工具

## 系统要求

- Python 3.7+
- 无需额外依赖（仅使用标准库）

## 安装

```bash
# 克隆或下载项目后，直接运行即可
cd open_antivirus
```

## 使用方法

### 1. 扫描文件或目录

```bash
# 扫描单个文件
python open_antivirus.py scan /path/to/file

# 扫描目录（递归）
python open_antivirus.py scan /path/to/directory

# 扫描目录（不递归）
python open_antivirus.py scan /path/to/directory --no-recursive

# 扫描并自动隔离受感染文件
python open_antivirus.py scan /path/to/directory --quarantine
```

### 2. 查看扫描报告

```bash
python open_antivirus.py report
```

### 3. 更新病毒特征库

```bash
python open_antivirus.py update
```

## 项目结构

```
open_antivirus/
├── open_antivirus.py    # 主程序
├── virus_db.json        # 病毒特征数据库（自动生成）
├── scan_report.json     # 扫描报告（扫描后生成）
└── quarantine/          # 隔离区目录（需要时创建）
```

## 核心组件

### 1. VirusDatabase (病毒特征库)
- 存储已知病毒的哈希值和元数据
- 支持动态添加新特征
- JSON 格式持久化存储

### 2. HeuristicScanner (启发式扫描器)
- 检测可疑的字节模式
- 计算文件熵值（检测加密/压缩内容）
- 识别潜在的恶意行为特征

### 3. OpenAntivirus (主引擎)
- 协调特征码扫描和启发式扫描
- 生成综合扫描结果
- 管理文件隔离

## 威胁等级

| 等级 | 说明 |
|------|------|
| 低 | 轻微可疑，可能是误报 |
| 中 | 中等风险，需要进一步检查 |
| 高 | 高风险，很可能是恶意软件 |
| 严重 | 确认的威胁，立即处理 |

## 示例输出

```
============================================================
扫描报告摘要
============================================================
总文件数: 150
感染文件: 2
安全文件: 148

⚠️  发现的威胁:
  - /path/to/suspicious.exe
    威胁: Generic.Trojan
    等级: 高
    详情: 发现可疑模式: MZ; 发现可疑模式: powershell
============================================================
```

## 添加自定义病毒特征

编辑 `virus_db.json` 或通过代码添加：

```python
from open_antivirus import VirusDatabase, VirusSignature, ThreatLevel

db = VirusDatabase()
db.add_signature(VirusSignature(
    name="Custom.Threat",
    signature="文件的 SHA256 哈希",
    threat_level=ThreatLevel.HIGH,
    description="自定义威胁描述",
    category="自定义"
))
```

## 注意事项

⚠️ **重要声明**: 
- 本项目仅供学习和研究使用
- 不要作为生产环境的主要安全防护方案
- 建议与商业杀毒软件配合使用
- 病毒特征库需要持续更新以保持有效性

## 扩展开发

### 添加新的检测模式

在 `HeuristicScanner` 类中添加新的可疑模式：

```python
self.suspicious_patterns.append((b'your_pattern', score_points))
```

### 集成云查杀

可以扩展 `VirusDatabase` 类，添加远程 API 查询功能。

### 实时保护

可以实现文件系统监控（如使用 `watchdog` 库）来实现实时保护。

## 许可证

MIT License - 自由使用、修改和分发

## 贡献

欢迎提交 Issue 和 Pull Request！

## 免责声明

本软件提供的功能仅供教育和研究目的。作者不对因使用本软件造成的任何损失承担责任。在生产环境中，请使用经过验证的商业杀毒解决方案。
