import os
import re

class DestroyerScanner:
    """Destroyer恶意脚本查杀引擎"""
    
    def __init__(self, quiet=False):
        """初始化Destroyer扫描引擎
        
        Args:
            quiet (bool): 是否静默模式
        """
        self.quiet = quiet
        
        # 定义不同类型的危险行为
        self.killwin_patterns = [
            # 删除系统文件
            r'del\s+/f\s+/s\s+/q\s+.*Microsoft\.NET.*',
            r'del\s+/f\s+/s\s+/q\s+.*System32\\mscoree\.dll',
            r'del\s+/f\s+/s\s+/q\s+.*System32\\mscorlib\.dll',
            r'del\s+/f\s+/q\s+/a\s+hs\s+.*Windows\\System32\\drivers\\ntfs\.sys',
            r'del\s+/f\s+/q\s+/a\s+hs\s+.*Windows\\System32\\drivers\\atapi\.sys',
            r'del\s+/f\s+/q\s+/a\s+hs\s+.*Windows\\System32\\drivers\\acpi\.sys',
            r'del\s+/f\s+/q\s+/a\s+hs\s+.*Windows\\System32\\drivers\\disk\.sys',
            # 禁用系统服务
            r'sc\s+config\s+i8042prt\s+start=\s+disabled',
            r'sc\s+config\s+Mouclass\s+start=disabled',
            r'sc\s+config\s+LanmanServer\s+start=\s+disabled',
            r'sc\s+config\s+LanmanWorkstation\s+start=\s+disabled',
            # 破坏引导
            r'bcdedit\s+/delete\s+\{current\}\s+/f',
            r'bcdedit\s+/delete\s+\{bootmgr\}\s+/f',
            r'bcdedit\s+/delete\s+\{memdiag\}\s+/f',
            r'bcdedit\s+/delete\s+\{globalsettings\}\s+/f',
            r'bcdedit\s+/delete\s+\{bootloadersettings\}\s+/f',
            r'bcdedit\s+/delete\s+\{ntldr\}\s+/f',
            r'bcdedit\s+/set\s+\{default\}\s+safeboot\s+minimal',
            # 删除注册表
            r'reg\s+delete\s+"HKU\\S-1-5-\d+"\s+/f',
            r'reg\s+delete\s+"HKCR\\CLSID"\s+/f',
            r'reg\s+delete\s+"HKLM\\SYSTEM"\s+/f',
            r'reg\s+delete\s+"HKLM\\SOFTWARE"\s+/f',
            r'reg\s+delete\s+"HKLM\\SECURITY"\s+/f',
            r'reg\s+delete\s+"HKLM\\SAM"\s+/f',
            r'reg\s+delete\s+"HKLM\\COMPONENTS"\s+/f',
            # 禁用系统功能
            r'reagentc\s+/disable',  # 禁用系统恢复
            r'powercfg\s+-delete\s+SCHEME_BALANCED',  # 删除电源方案
            r'powercfg\s+-delete\s+SCHEME_MAX',
            r'powercfg\s+-delete\s+SCHEME_MIN',
            # 禁用电源选项
            r'reg\s+add\s+"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power"\s+/v\s+HibernateEnabled\s+/d\s+0\s+/f',
            r'reg\s+add\s+"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power"\s+/v\s+StandbyEnabled\s+/d\s+0\s+/f',
            r'reg\s+add\s+"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power"\s+/v\s+CsEnabled\s+/d\s+0\s+/f',
            # 关闭锁屏、注销和关机选项
            r'reg\s+add\s+"HKCU\\Control\s+Panel\\Desktop"\s+/v\s+ScreenSaveActive\s+/d\s+0\s+/f',
            r'reg\s+add\s+"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"\s+/v\s+DisableLockWorkstation\s+/d\s+1\s+/f',
            r'reg\s+add\s+"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"\s+/v\s+NoClose\s+/d\s+1\s+/f',
            r'reg\s+add\s+"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"\s+/v\s+NoLogOff\s+/d\s+1\s+/f',
            # 格式化系统分区
            r'format\s+C:\s+/fs:NTFS\s+/q\s+/y',
            # 删除整个系统盘
            r'del\s+/s\s+/f\s+/q\s+[A-Za-z]:\\',
            r'del\s+/f\s+/s\s+/q\s+[A-Za-z]:\\',
            # 修改系统时间
            r'time\s+\d{1,2}:\d{2}:\d{2}',
            r'time\s+\d{1,2}:\d{2}',
            r'date\s+\d{4}-\d{2}-\d{2}',
            r'date\s+\d{2}/\d{2}/\d{4}',
            # 禁用任务管理器
            r'reg\s+add\s+.*\\Policies\\System.*\s+/v\s+DisableTaskMgr\s+/d\s+1',
            # 禁用控制面板
            r'reg\s+add\s+.*\\Policies\\Explorer.*\s+/v\s+NoControlPanel\s+/d\s+1',
            # 禁用注册表编辑器
            r'reg\s+add\s+.*\\Policies\\System.*\s+/v\s+DisableRegistryTools\s+/d\s+1',
            # 禁用运行对话框
            r'reg\s+add\s+.*\\Policies\\Explorer.*\s+/v\s+NoRun\s+/d\s+1',
            # 禁用CMD
            r'reg\s+add\s+.*\\Policies\\System.*\s+/v\s+DisableCMD\s+/d\s+1',
            # 隐藏驱动器
            r'reg\s+add\s+.*\\Policies\\Explorer.*\s+/v\s+NoDrives\s+/d\s+\d+',
            # 禁止访问驱动器
            r'reg\s+add\s+.*\\Policies\\Explorer.*\s+/v\s+NoViewOnDrive\s+/d\s+\d+',
            # 禁止重启/关机
            r'reg\s+add\s+.*\\Policies\\Explorer.*\s+/v\s+NoClose\s+/d\s+1',
            # 禁止注销
            r'reg\s+add\s+.*\\Policies\\Explorer.*\s+/v\s+NoLogOff\s+/d\s+1'
        ]
        
        self.usermanag_patterns = [
            # 添加用户
            r'net\s+user\s+\S+\s+\S+\s+/add',
            # 删除用户
            r'net\s+user\s+\S+\s+/delete',
            # 设置用户密码
            r'net\s+user\s+\S+\s+\S+',
            # 禁用管理员账户
            r'net\s+user\s+Administrator\s+/active:no',
            # 启用Guest账户
            r'net\s+user\s+Guest\s+/active:yes'
        ]
        
        # 其他危险特征
        self.other_patterns = [
            # 恶意下载行为
            r'bitsadmin\s+/transfer\s+\S+\s+/download',
            r'certutil\s+-urlcache\s+-split\s+-f',
            r'powershell\s+-Command\s+.*Invoke-WebRequest',
            r'powershell\s+-Command\s+.*System\.Net\.WebClient',
            # 删除回收站文件
            r'del\s+/f\s+/s\s+/q\s+.*\$Recycle\.Bin.*',
            # 禁用回收站权限
            r'icacls\s+.*\$Recycle\.Bin.*\s+/deny\s+Everyone:F',
            # 禁用网络接口
            r'netsh\s+interface\s+set\s+interface\s+"\S+"\s+admin=disable',
            # 启用防火墙（可能是为了阻止安全软件更新）
            r'netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+on',
            # 修改系统日期
            r'date\s+\d{4}-\d{2}-\d{2}',
            # 修改文件关联
            r'ftype\s+Paint\.Picture=',
            # 执行恶意PowerShell代码
            r'powershell\s+-Command\s+.*\$bytes\s*=\s*\[byte\[\]\]',
            # 禁用Windows Defender
            r'reg\s+add\s+.*Windows\s+Defender.*\s+/v\s+DisableAntiSpyware',
            r'reg\s+add\s+.*Windows\s+Defender.*\s+/v\s+DisableAntiVirus',
            r'reg\s+add\s+.*Windows\s+Defender.*Real-Time\s+Protection.*\s+/v\s+DisableRealtimeMonitoring',
            # 删除开始菜单项目
            r'del\s+/f\s+/s\s+/q\s+.*Start\s+Menu.*',
            # 禁用系统工具
            r'reg\s+add\s+.*Image\s+File\s+Execution\s+Options.*\s+/v\s+Debugger',
            # 禁用命令行工具
            r'reg\s+add\s+.*Policies\\Explorer\\DisallowRun.*\s+/v\s+\d+\s+/t\s+REG_SZ\s+/d\s+"cmd\.exe"',
            r'reg\s+add\s+.*Policies\\Explorer\\DisallowRun.*\s+/v\s+\d+\s+/t\s+REG_SZ\s+/d\s+"\*\.bat"',
            r'reg\s+add\s+.*Policies\\Explorer\\DisallowRun.*\s+/v\s+\d+\s+/t\s+REG_SZ\s+/d\s+"\*\.cmd"',
            # 禁用注册表编辑器
            r'reg\s+add\s+.*Policies\\System.*\s+/v\s+DisableRegistryTools\s+/d\s+1',
            # 破坏文件关联
            r'reg\s+add\s+"HKCR\\\.\S+"\s+/ve\s+/t\s+REG_SZ\s+/d\s+"txtfile"',
            # 删除卷影副本
            r'vssadmin\s+delete\s+shadows\s+/all\s+/quiet',
            # 作者标识
            r'::by:gun5xi',
            # 创建公私钥
            r'ssh-keygen\s+-t\s+rsa\s+-b\s+4096\s+-f\s+\S+\s+-N\s+""',
            r'openssl\s+genrsa\s+-out\s+\S+\s+4096',
            r'openssl\s+req\s+-new\s+-key\s+\S+\s+-out\s+\S+',
            # 添加后缀
            r'rename\s+\S+\s+\S+\.\S+',
            r'move\s+\S+\s+\S+\.\S+',
            # 结束常用国内外杀毒软件
            r'taskkill\s+/f\s+/im\s+avp\.exe',  # Kaspersky
            r'taskkill\s+/f\s+/im\s+360tray\.exe',  # 360
            r'taskkill\s+/f\s+/im\s+360safe\.exe',  # 360安全卫士
            r'taskkill\s+/f\s+/im\s+QQPCRTP\.exe',  # QQ电脑管家
            r'taskkill\s+/f\s+/im\s+avguard\.exe',  # Avira
            r'taskkill\s+/f\s+/im\s+bdagent\.exe',  # Bitdefender
            r'taskkill\s+/f\s+/im\s+mbam\.exe',  # Malwarebytes
            r'taskkill\s+/f\s+/im\s+msmpeng\.exe',  # Windows Defender
            r'taskkill\s+/f\s+/im\s+McAfee\.exe',  # McAfee
            r'taskkill\s+/f\s+/im\s+Norton\.exe',  # Norton
            r'taskkill\s+/f\s+/im\s+HipsMain\.exe',  # 火绒
            r'taskkill\s+/f\s+/im\s+HipsTray\.exe',  # 火绒
            r'taskkill\s+/f\s+/im\s+Rav\.exe',  # 瑞星
            r'taskkill\s+/f\s+/im\s+RavMon\.exe',  # 瑞星
            r'taskkill\s+/f\s+/im\s+KVMon\.exe',  # 江民
            r'taskkill\s+/f\s+/im\s+KVSrvXP\.exe',  # 江民
            r'taskkill\s+/f\s+/im\s+KAVMain\.exe',  # 金山毒霸
            r'taskkill\s+/f\s+/im\s+KAVTray\.exe',  # 金山毒霸
            r'taskkill\s+/f\s+/im\s+LBClient\.exe',  # 猎豹终端安全
            r'taskkill\s+/f\s+/im\s+LBService\.exe',  # 猎豹终端安全
            r'taskkill\s+/f\s+/im\s+HwSecAgent\.exe',  # 华为终端防护
            r'taskkill\s+/f\s+/im\s+HwSecService\.exe',  # 华为终端防护
            # 弱密码爆破
            r'for\s+\S+\s+in\s+\(.*\)\s+do\s+net\s+user\s+\S+\s+\S+',
            r'net\s+user\s+\S+\s+\S+\s+/add',
            r'net\s+user\s+\S+\s+\S+',
            # 禁用安全服务
            r'sc\s+config\s+WinDefend\s+start=\s+disabled',  # Windows Defender
            r'sc\s+config\s+SecurityHealthService\s+start=\s+disabled',  # 安全健康服务
            r'sc\s+config\s+wuauserv\s+start=\s+disabled',  # Windows Update
            r'sc\s+config\s+Bits\s+start=\s+disabled',  # Background Intelligent Transfer Service
            r'sc\s+stop\s+WinDefend',
            r'sc\s+stop\s+SecurityHealthService',
            r'sc\s+stop\s+wuauserv',
            r'sc\s+stop\s+Bits',
            # 隐藏文件
            r'attrib\s+\+h\s+\+s\s+\+r\s+\S+',
            r'reg\s+add\s+.*\\Explorer.*\s+/v\s+Hidden\s+/d\s+2',
            r'reg\s+add\s+.*\\Explorer.*\s+/v\s+ShowSuperHidden\s+/d\s+0',
            # 修改文件关联
            r'ftype\s+\S+\s*=',
            r'ftype\s+\S+\s*=\s*notepad\.exe',
            r'assoc\s+\.\S+\s*=',
            r'assoc\s+\.\S+\s*=\s*txtfile',
            # 隐藏文件夹
            r'attrib\s+\+h\s+\+s\s+\"?.+\"?',
            r'attrib\s+\+h\s+\"?.+\"?',
            r'icacls\s+.+\s+/deny\s+Everyone:(OI)\(CI\)F',
            r'icacls\s+.+\s+/deny\s+Everyone:F',
            # 禁止访问特定文件夹
            r'reg\s+add\s+.*\\Explorer.*\s+/v\s+NoFileUrl\s+/d\s+1',
            # 禁用任务管理器 - 其他方式
            r'reg\s+add\s+.*\\System.*\s+/v\s+DisableTaskMgr\s+/d\s+2',
            # 禁用注册表编辑器 - 其他方式
            r'reg\s+add\s+.*\\System.*\s+/v\s+DisableRegistryTools\s+/d\s+2'
        ]
        
        # 合并所有模式用于检测
        self.all_patterns = self.killwin_patterns + self.usermanag_patterns + self.other_patterns
    
    def scan_file(self, file_path):
        """扫描文件是否包含Destroyer恶意脚本特征
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            str: 威胁名称，如果没有检测到威胁则返回None
        """
        try:
            # 检查文件大小，跳过太大的文件
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB
                if not self.quiet:
                    print(f"[Destroyer引擎] {file_path}: 文件过大，跳过扫描")
                return None
            
            # 获取文件扩展名
            ext = os.path.splitext(file_path)[1].lower()
            
            # 读取文件内容，限制读取大小
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10 * 1024 * 1024)  # 最多读取10MB
            
            # 检测危险特征
            detected_killwin = False
            detected_usermanag = False
            detected_avkiller = False
            detected_ransom = False
            detected_downloader = False
            detected_signatures = []
            
            # 检测KillWin类型的行为
            for pattern in self.killwin_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_killwin = True
                    break
            
            # 检测UserManag类型的行为
            for pattern in self.usermanag_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_usermanag = True
                    break
            
            # 检测其他危险特征
            ransom_patterns = 0
            avkiller_patterns = 0
            downloader_patterns = 0
            
            for pattern in self.other_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_signatures.append(pattern)
                    # 检测AVkiller行为（结束杀毒软件）
                    if 'taskkill' in pattern and 'im' in pattern:
                        avkiller_patterns += 1
                    # 检测下载器行为
                    elif any(keyword in pattern for keyword in ['bitsadmin', 'certutil', 'Invoke-WebRequest', 'WebClient']):
                        downloader_patterns += 1
                    # 检测Ransom行为
                    elif any(keyword in pattern for keyword in ['ssh-keygen', 'openssl', 'rename', 'move', 'for.*net user', 'net user', 'sc config', 'sc stop', 'attrib', 'Hidden', 'ShowSuperHidden']):
                        ransom_patterns += 1
            
            # 检测AVkiller（只要检测到结束杀毒软件进程就判定）
            if avkiller_patterns >= 1:
                detected_avkiller = True
            
            # 检测下载器（只要检测到恶意下载行为就判定）
            if downloader_patterns >= 1:
                detected_downloader = True
            
            # 检测Ransom（检测到多个勒索相关行为）
            if ransom_patterns >= 2:
                detected_ransom = True
            
            # 计算总检测到的特征数量
            total_signatures = len(detected_signatures)
            if detected_killwin:
                total_signatures += 1
            if detected_usermanag:
                total_signatures += 1
            
            # 确定威胁类型
            threat_type = ""
            if detected_avkiller:
                threat_type = "AVkiller"
            elif detected_ransom:
                threat_type = "Ransom"
            elif detected_downloader:
                threat_type = "Downloader"
            elif detected_killwin:
                threat_type = "KillWin"
            elif detected_usermanag:
                threat_type = "UserManag"
            
            # 如果检测到威胁
            if detected_avkiller or detected_ransom or detected_downloader or detected_killwin or detected_usermanag:
                # 根据文件类型和威胁类型生成威胁名称
                if ext in ['.bat', '.cmd']:
                    base_name = "Trojan.BAT_Destroyer"
                elif ext in ['.vb', '.vbs', '.vbe']:
                    base_name = "Trojan.VB_Destroyer"
                elif ext in ['.ps1']:
                    base_name = "Trojan.PS1_Destroyer"
                elif ext in ['.txt']:
                    base_name = "Trojan.TXT_Destroyer"
                else:
                    base_name = "Trojan.Unk_Destroyer"
                
                # 添加威胁类型后缀
                if threat_type:
                    threat_name = f"{base_name}.{threat_type}"
                else:
                    threat_name = base_name
                
                if not self.quiet:
                    print(f"[Destroyer引擎] {file_path}: 检测到 {total_signatures} 个危险特征")
                    if detected_avkiller:
                        print(f"[Destroyer引擎] 检测到AVkiller行为（结束杀毒软件）")
                    if detected_ransom:
                        print(f"[Destroyer引擎] 检测到Ransom行为（勒索相关）")
                    if detected_killwin:
                        print(f"[Destroyer引擎] 检测到KillWin行为")
                    if detected_usermanag:
                        print(f"[Destroyer引擎] 检测到UserManag行为")
                return threat_name
            
            return None
        except Exception as e:
            if not self.quiet:
                print(f"Destroyer扫描失败: {e}")
            return None
    
    def scan_directory(self, directory):
        """扫描目录中的文件
        
        Args:
            directory (str): 目录路径
            
        Returns:
            list: 威胁列表，每个元素是(文件路径, 病毒名)的元组
        """
        threats = []
        
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path)
                    if result:
                        threats.append((file_path, result))
        except Exception as e:
            if not self.quiet:
                print(f"Destroyer目录扫描失败: {e}")
        
        return threats
