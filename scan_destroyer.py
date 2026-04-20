import os
import sys
from destroyer_scanner import DestroyerScanner

def scan_file(file_path, quiet=False):
    """扫描单个文件是否包含 Destroyer 恶意脚本特征"""
    scanner = DestroyerScanner(quiet=quiet)
    
    if not os.path.exists(file_path):
        print(f"错误：文件不存在 - {file_path}")
        return None
    
    result = scanner.scan_file(file_path)
    
    if result:
        print(f"[检测结果] {file_path}")
        print(f"  威胁类型: {result}")
    else:
        print(f"[检测结果] {file_path}")
        print("  未检测到威胁")
    
    return result

def scan_directory(directory, quiet=False):
    """扫描目录下的所有文件"""
    scanner = DestroyerScanner(quiet=quiet)
    
    if not os.path.exists(directory):
        print(f"错误：目录不存在 - {directory}")
        return []
    
    print(f"正在扫描目录: {directory}")
    print("-" * 50)
    
    threats = []
    files_scanned = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            files_scanned += 1
            
            result = scanner.scan_file(file_path)
            if result:
                threats.append((file_path, result))
    
    print("-" * 50)
    print(f"\n扫描完成！")
    print(f"扫描文件总数: {files_scanned}")
    print(f"检测到威胁数: {len(threats)}")
    
    if threats:
        print("\n=== 威胁列表 ===")
        for path, threat_type in threats:
            print(f"  {threat_type} - {path}")
    
    return threats

def print_help():
    """显示帮助信息"""
    print("Destroyer 恶意脚本扫描工具")
    print("用法:")
    print("  python scan_destroyer.py <文件路径|目录路径> [--quiet]")
    print("  python scan_destroyer.py --help")
    print("")
    print("参数:")
    print("  文件路径|目录路径    要扫描的文件或目录")
    print("  --quiet             静默模式，减少输出")
    print("  --help              显示此帮助信息")
    print("")
    print("示例:")
    print("  python scan_destroyer.py C:\\path\\to\\file.bat")
    print("  python scan_destroyer.py D:\\Downloads")
    print("  python scan_destroyer.py E:\\Scripts --quiet")

if __name__ == "__main__":
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        sys.exit(0)
    
    target = sys.argv[1]
    quiet_mode = "--quiet" in sys.argv
    
    if os.path.isfile(target):
        scan_file(target, quiet=quiet_mode)
    elif os.path.isdir(target):
        scan_directory(target, quiet=quiet_mode)
    else:
        print(f"错误：路径不存在 - {target}")
        sys.exit(1)

    input("\n按回车键退出...")
