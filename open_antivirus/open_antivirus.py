#!/usr/bin/env python3
"""
OpenAntivirus - 开源杀毒软件核心引擎
功能：
1. 基于特征码的病毒扫描
2. 启发式扫描（可疑行为检测）
3. 文件完整性校验
4. 实时保护（可选）
5. 报告生成

使用方法:
    python open_antivirus.py scan <file_or_directory>
    python open_antivirus.py update
    python open_antivirus.py report
"""

import os
import sys
import hashlib
import json
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """威胁等级"""
    LOW = "低"
    MEDIUM = "中"
    HIGH = "高"
    CRITICAL = "严重"


@dataclass
class VirusSignature:
    """病毒特征码"""
    name: str
    signature: str  # MD5/SHA256 哈希
    threat_level: ThreatLevel
    description: str
    category: str  # 病毒类型


@dataclass
class ScanResult:
    """扫描结果"""
    file_path: str
    is_infected: bool
    virus_name: Optional[str]
    threat_level: Optional[str]
    scan_time: str
    file_hash: str
    heuristic_score: float
    details: str


class VirusDatabase:
    """病毒特征库"""
    
    def __init__(self, db_path: str = "virus_db.json"):
        self.db_path = db_path
        self.signatures: List[VirusSignature] = []
        self.load_database()
    
    def load_database(self):
        """加载病毒数据库"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.signatures = [
                        VirusSignature(**sig) for sig in data.get('signatures', [])
                    ]
                logger.info(f"已加载 {len(self.signatures)} 个病毒特征")
            except Exception as e:
                logger.error(f"加载病毒数据库失败: {e}")
                self._create_default_database()
        else:
            self._create_default_database()
    
    def _create_default_database(self):
        """创建默认病毒特征库（示例）"""
        self.signatures = [
            VirusSignature(
                name="EICAR-Test-File",
                signature="44d88612fea8a8f36de82e1278abb02f",
                threat_level=ThreatLevel.LOW,
                description="EICAR 测试文件（无害测试用）",
                category="测试"
            ),
            VirusSignature(
                name="Generic.Trojan",
                signature="example_malware_hash_1",
                threat_level=ThreatLevel.HIGH,
                description="通用木马程序",
                category="木马"
            ),
            VirusSignature(
                name="Ransomware.Generic",
                signature="example_ransomware_hash",
                threat_level=ThreatLevel.CRITICAL,
                description="勒索软件",
                category="勒索软件"
            ),
        ]
        self.save_database()
        logger.info("已创建默认病毒数据库")
    
    def save_database(self):
        """保存病毒数据库"""
        data = {
            'last_updated': datetime.now().isoformat(),
            'signatures': [
                {
                    'name': sig.name,
                    'signature': sig.signature,
                    'threat_level': sig.threat_level.value,
                    'description': sig.description,
                    'category': sig.category
                } for sig in self.signatures
            ]
        }
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def check_signature(self, file_hash: str) -> Optional[VirusSignature]:
        """检查文件哈希是否匹配已知病毒"""
        for sig in self.signatures:
            if sig.signature.lower() == file_hash.lower():
                return sig
        return None
    
    def add_signature(self, signature: VirusSignature):
        """添加新的病毒特征"""
        self.signatures.append(signature)
        self.save_database()


class HeuristicScanner:
    """启发式扫描器 - 检测可疑行为"""
    
    def __init__(self):
        self.suspicious_patterns = [
            (b'MZ', 10),  # PE 文件头
            (b'This program cannot be run in DOS mode', 15),
            (b'powershell', 20),
            (b'cmd.exe', 25),
            (b'reg add', 30),
            (b'schtasks', 25),
            (b'WScript.Shell', 30),
            (b'CreateRemoteThread', 40),
            (b'VirtualAllocEx', 35),
            (b'WriteProcessMemory', 35),
        ]
    
    def scan(self, file_path: str) -> Tuple[float, List[str]]:
        """
        执行启发式扫描
        返回: (风险分数, 可疑项列表)
        """
        score = 0.0
        findings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # 读取前1MB
                
                for pattern, points in self.suspicious_patterns:
                    if pattern in content:
                        score += points
                        findings.append(f"发现可疑模式: {pattern.decode('utf-8', errors='ignore')}")
                
                # 检查高熵值（可能加密/压缩）
                if len(content) > 0:
                    entropy = self._calculate_entropy(content)
                    if entropy > 7.5:
                        score += 20
                        findings.append(f"高熵值检测到: {entropy:.2f}（可能加密或压缩）")
                
                # 检查文件大小异常
                if len(content) == 0:
                    score += 10
                    findings.append("空文件")
                    
        except Exception as e:
            logger.error(f"启发式扫描失败 {file_path}: {e}")
        
        return min(score, 100.0), findings
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算数据熵值"""
        if not data:
            return 0.0
        
        entropy = 0.0
        byte_counts = {}
        
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * (probability and (probability * 0.6931471805599453) or 0)
        
        return entropy / 0.6931471805599453  # 转换为 log2


class OpenAntivirus:
    """开源杀毒软件主类"""
    
    def __init__(self, db_path: str = "virus_db.json"):
        self.virus_db = VirusDatabase(db_path)
        self.heuristic_scanner = HeuristicScanner()
        self.scan_results: List[ScanResult] = []
    
    def calculate_file_hash(self, file_path: str) -> str:
        """计算文件 SHA256 哈希"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"计算哈希失败 {file_path}: {e}")
            return ""
    
    def scan_file(self, file_path: str) -> ScanResult:
        """扫描单个文件"""
        logger.info(f"正在扫描: {file_path}")
        
        start_time = datetime.now()
        file_hash = self.calculate_file_hash(file_path)
        
        # 特征码扫描
        virus_sig = self.virus_db.check_signature(file_hash)
        
        # 启发式扫描
        heuristic_score, heuristic_findings = self.heuristic_scanner.scan(file_path)
        
        is_infected = virus_sig is not None or heuristic_score >= 50
        
        result = ScanResult(
            file_path=file_path,
            is_infected=is_infected,
            virus_name=virus_sig.name if virus_sig else None,
            threat_level=virus_sig.threat_level.value if virus_sig else (
                ThreatLevel.HIGH.value if heuristic_score >= 70 else
                ThreatLevel.MEDIUM.value if heuristic_score >= 50 else
                ThreatLevel.LOW.value
            ),
            scan_time=start_time.isoformat(),
            file_hash=file_hash,
            heuristic_score=heuristic_score,
            details="; ".join(heuristic_findings) if heuristic_findings else "未发现问题"
        )
        
        self.scan_results.append(result)
        
        if is_infected:
            logger.warning(f"⚠️  发现威胁: {result.virus_name or '可疑文件'} ({result.threat_level})")
        else:
            logger.info(f"✓ 安全: {file_path}")
        
        return result
    
    def scan_directory(self, dir_path: str, recursive: bool = True) -> List[ScanResult]:
        """扫描目录"""
        results = []
        path = Path(dir_path)
        
        if not path.exists():
            logger.error(f"路径不存在: {dir_path}")
            return results
        
        files_to_scan = path.rglob('*') if recursive else path.glob('*')
        
        for file_path in files_to_scan:
            if file_path.is_file():
                # 跳过某些文件类型
                if file_path.suffix.lower() in ['.log', '.tmp', '.swp']:
                    continue
                
                try:
                    result = self.scan_file(str(file_path))
                    results.append(result)
                except Exception as e:
                    logger.error(f"扫描失败 {file_path}: {e}")
        
        return results
    
    def scan(self, target: str, recursive: bool = True) -> List[ScanResult]:
        """扫描目标（文件或目录）"""
        target_path = Path(target)
        
        if target_path.is_file():
            return [self.scan_file(target)]
        elif target_path.is_dir():
            return self.scan_directory(target, recursive)
        else:
            logger.error(f"无效的目标: {target}")
            return []
    
    def generate_report(self, output_file: str = "scan_report.json"):
        """生成扫描报告"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_files': len(self.scan_results),
            'infected_files': sum(1 for r in self.scan_results if r.is_infected),
            'clean_files': sum(1 for r in self.scan_results if not r.is_infected),
            'results': [asdict(r) for r in self.scan_results]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"扫描报告已保存到: {output_file}")
        
        # 打印摘要
        print("\n" + "="*60)
        print("扫描报告摘要")
        print("="*60)
        print(f"总文件数: {report['total_files']}")
        print(f"感染文件: {report['infected_files']}")
        print(f"安全文件: {report['clean_files']}")
        
        if report['infected_files'] > 0:
            print("\n⚠️  发现的威胁:")
            for result in self.scan_results:
                if result.is_infected:
                    print(f"  - {result.file_path}")
                    print(f"    威胁: {result.virus_name or '可疑行为'}")
                    print(f"    等级: {result.threat_level}")
                    print(f"    详情: {result.details}")
        
        print("="*60)
        
        return report
    
    def quarantine_file(self, file_path: str, quarantine_dir: str = "quarantine"):
        """隔离受感染文件"""
        try:
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # 生成唯一文件名
            file_name = Path(file_path).name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_path = os.path.join(quarantine_dir, f"{timestamp}_{file_name}")
            
            # 移动文件到隔离区
            os.rename(file_path, quarantine_path)
            
            # 记录隔离信息
            quarantine_info = {
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'timestamp': timestamp,
                'reason': next((r.details for r in self.scan_results 
                              if r.file_path == file_path), "未知")
            }
            
            with open(os.path.join(quarantine_dir, 'quarantine_log.json'), 'a') as f:
                f.write(json.dumps(quarantine_info, ensure_ascii=False) + '\n')
            
            logger.info(f"文件已隔离: {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"隔离失败: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="OpenAntivirus - 开源杀毒软件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python open_antivirus.py scan /path/to/file
  python open_antivirus.py scan /path/to/directory --recursive
  python open_antivirus.py report
  python open_antivirus.py update
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 扫描命令
    scan_parser = subparsers.add_parser('scan', help='扫描文件或目录')
    scan_parser.add_argument('target', help='要扫描的文件或目录')
    scan_parser.add_argument('--no-recursive', action='store_true', 
                            help='不递归扫描子目录')
    scan_parser.add_argument('--quarantine', action='store_true',
                            help='自动隔离受感染文件')
    
    # 报告命令
    subparsers.add_parser('report', help='生成扫描报告')
    
    # 更新命令
    subparsers.add_parser('update', help='更新病毒特征库')
    
    args = parser.parse_args()
    
    antivirus = OpenAntivirus()
    
    if args.command == 'scan':
        results = antivirus.scan(args.target, recursive=not args.no_recursive)
        antivirus.generate_report()
        
        if args.quarantine:
            for result in results:
                if result.is_infected:
                    antivirus.quarantine_file(result.file_path)
    
    elif args.command == 'report':
        if not antivirus.scan_results:
            print("没有可用的扫描结果。请先执行扫描。")
        else:
            antivirus.generate_report()
    
    elif args.command == 'update':
        print("病毒特征库更新功能（示例）")
        print("在实际应用中，这里会从远程服务器下载最新的病毒特征")
        antivirus.virus_db.save_database()
        print("✓ 病毒特征库已更新")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
