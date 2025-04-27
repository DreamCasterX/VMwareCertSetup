import os
import json
import subprocess
from colorama import init, Fore, Style
import re
import pyperclip

# Initialize colorama
init()


def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in ip.split('.'))
    except ValueError:
        return False


def mount_iso(iso_path):
    """掛載VCSA ISO並返回掛載的drive letter"""

    mount_drive = None
    result = subprocess.run(
        f'powershell "Mount-DiskImage -ImagePath \'{iso_path}\' -PassThru | Get-Volume | Select-Object -ExpandProperty DriveLetter"', 
        shell=True, 
        capture_output=True, 
        text=True
    )
    mount_drive = result.stdout.strip() + ":"
    return mount_drive

def get_vcsa_deploy_path(mount_drive):
    """獲取vcsa-deploy.exe的路徑"""
    
    # 使用 os.path.sep 來確保使用正確的路徑分隔符
    deploy_path = os.path.join(mount_drive + os.path.sep, "vcsa-cli-installer", "win32", "vcsa-deploy.exe")
    if not os.path.exists(deploy_path):
        raise FileNotFoundError(f"Unable to find vcsa-deploy tool: {deploy_path}")
    
    return deploy_path

def create_json_template(esxi_host, esxi_username, esxi_password, template_path, vm_name, deployment_network):
    """創建VCSA部署的JSON模板"""
    # 創建基本的部署配置  只是模板, 不會直接配置上面的參數 除非user沒有填
    config = {
        "__version": "2.13.0",
        "new_vcsa": {
            "esxi": {
                "hostname": esxi_host,
                "username": esxi_username,
                "password": esxi_password,
                "deployment_network": deployment_network,  # 使用用戶選擇的網絡
                "datastore": "datastore1"  # 使用預設的datastore1，您可能需要修改
            },
            "appliance": {
                "thin_disk_mode": True,
                "deployment_option": "medium",  # 可選: tiny, small, medium, large, etc.
                "name": vm_name  # vCenter虛擬機名稱
            },
            "network": {
                "ip_family": "ipv4",
                "mode": "static",
                "ip": "192.168.4.98",  # 設置為您想要的IP地址
                "prefix": "22",  # 子網掩碼位數
                "gateway": "192.168.4.1",  # 網關地址
                "dns_servers": [
                    "192.168.4.1"
                ],
                "system_name": "vc98.lenovo.com"  # FQDN或IP地址
            },
            "os": {
                "password": "Admin!23",  # root密碼
                "ntp_servers": "192.168.4.1",
                "ssh_enable": True
            },
            "sso": {
                "password": "Admin!23",  # SSO密碼
                "domain_name": "vsphere.local",
                "first_instance": True
            }
        },
        "ceip": {
            "settings": {
                "ceip_enabled": False
            }
        }
    }
    
    # 將配置寫入JSON文件
    with open(template_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    return template_path

def deploy_vcenter(vcsa_deploy_path, template_path):
    """使用vcsa-deploy工具部署vCenter"""
    # 構建命令
    cmd = [
        vcsa_deploy_path, 
        'install',
        template_path,
        '--accept-eula',
        '--no-ssl-certificate-verification',
        '--acknowledge-ceip',
    ]
    
    print(f"Executing deployment command: {' '.join(cmd)}")
    
    # 執行部署命令
    process = subprocess.Popen(
        cmd, 
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    
    # 實時輸出部署進度
    last_message = None  # 用於追踪上一次的信息
    for line in iter(process.stdout.readline, ''):
        current_line = line.strip()
        
        # 跳過空行
        if not current_line:
            continue
            
        # 如果是重複的信息，就不顯示
        if current_line == last_message:
            continue
            
        if 'OVF Tool' in line and 'Disk progress:' in line:
            # 顯示磁盤進度
            print(f"\r{current_line}", end='', flush=True)
            if '99%' in line or '100%' in line:
                print("\n", end='', flush=True)
        elif any(msg in line for msg in [
            'VCSA Deployment Progress Report',
            'required RPMs for the appliance',
            'Task: Run firstboot scripts',
            'VCSA Deployment is still running'
        ]):
            # 在同一行更新這些狀態信息
            print(f"\r{current_line}", end='', flush=True)
        elif any(service in line for service in [
            'VMware Authentication Framework',
            'VMware Identity Single Container Service',
            'VMware Security Token Service',
            'VMware vCenter-Services',
            'VMware Certificate Authority Service',
            'VMware vAPI Endpoint',
            'VMware vCenter Server',
            'VMware Service Control Agent',
            'VMware vSphere Profile-Driven Storage Service',
            'VMware Update Manager',
            'VMware VSAN Health Service',
            'VMware vService Manager',
            'VMware Hybrid VC Service',
            'VMware vStats Service',
            'VMware Content Library Service',
            'VMware Performance Charts',
            'VMware Postgres',
            'VMware License Service',
            'VMware Trust Management Service'
        ]):
            # 服務安裝信息換行顯示
            print(f"\n{current_line}")
        elif 'Error:' in line or 'error:' in line:
            # 錯誤信息換行並用紅色顯示
            print(f"\n{Fore.RED}{current_line}{Style.RESET_ALL}")
        elif 'successfully' in line.lower():
            # 成功信息換行並用綠色顯示
            print(f"\n{Fore.GREEN}{current_line}{Style.RESET_ALL}")
        else:
            # 其他非重複信息正常顯示
            print(current_line)
            
        last_message = current_line
    
    process.wait()
    
    # 檢查部署結果
    if process.returncode == 0:
        print(f"\n{Fore.GREEN}vCenter deployment successful!{Style.RESET_ALL}")
        return True
    else:
        print(f"\n{Fore.RED}vCenter deployment failed, exit code: {process.returncode}{Style.RESET_ALL}")
        return False

def unmount_iso(mount_drive, iso_path):
    """卸載ISO鏡像"""

    subprocess.run(f'powershell "Dismount-DiskImage -ImagePath \'{iso_path}\'"', shell=True)


def main():

    print(
    f"""{Fore.YELLOW}
_________________________________________________________________________________________
<Prerequisites>
To move forward, make sure you've already completed the following:
1. Downloaded the VCSA image (.iso) and placed it in the current directory
2. Created a DNS hostname and IP for vCenter VM on DHCP server (ex: vc50 -> 192.168.4.50)
_________________________________________________________________________________________{Style.RESET_ALL}
"""
    )
            
    # 檢查vCenter ISO是否存在
    current_dir = os.getcwd()
    iso_files = [f for f in os.listdir(current_dir) if f.lower().endswith('.iso')]

    if not iso_files:
        print(f"{Fore.YELLOW}VCSA ISO file not found in the current directory.{Style.RESET_ALL}")

    while True:   
        if not iso_files:
            while True:
                response = input("Please place VCSA ISO file in the current directory to continue (y/n): ").strip().lower()
                if response in ['y', 'n']:
                    break
            
            if response == 'y':
                # 重新檢查檔案是否存在
                iso_files = [f for f in os.listdir(current_dir) if f.lower().endswith('.iso')]  # 更新 iso_files
                if iso_files:
                    break
            elif response == 'n':
                return
        else:
            break

    # 返回找到的第一個.iso文件
    iso_path = os.path.join(current_dir, iso_files[0])

    # 預設參數
    default_TC_datastore = "datastore1"
    default_TC_username = "root"
    default_TC_host = "10.241.180.125"
    default_TC_password = "Lenovo-123"   
    default_VC_prefix = "22"
    default_VC_gateway = "192.168.4.1"
    default_VC_dns_servers = "192.168.4.1"
    default_VC_root_password = "Admin!23"
    default_VC_sso_password = "Admin!23"
    default_VC_deployment_network = "All-Net網路-1GB-vmnic1"  # VM Network


    # 配置TC
    while True:
        esxi_host = input(f"Enter TC IP address <press Enter to accept default {Fore.CYAN}{default_TC_host}{Style.RESET_ALL}>: ").strip()
        if esxi_host == "":
            esxi_host = default_TC_host
        if validate_ip(esxi_host):
            break
        else:
            print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")
    esxi_username = input(f"Enter TC username <press Enter to accept default {Fore.CYAN}{default_TC_username}{Style.RESET_ALL}>: ").strip()
    if esxi_username == "":
        esxi_username = default_TC_username
    esxi_password = input(f"Enter TC password <press Enter to accept default {Fore.CYAN}{default_TC_password}{Style.RESET_ALL}>: ").strip()
    if esxi_password == "":
        esxi_password = default_TC_password
    esxi_datastore = input(f"Enter TC datastore <press Enter to accept default {Fore.CYAN}{default_TC_datastore}{Style.RESET_ALL}>: ").strip()
    if esxi_datastore == "":
        esxi_datastore = default_TC_datastore

    print("")

    # 配置vCenter
    while True:
        vm_name = input(f"Enter vCenter VM name: ").strip()
        if vm_name:
            break
    
    network_config = {}
    while True:
        network_config['ip'] = input(f"Enter vCenter IP address: ").strip()
        if validate_ip(network_config['ip']):
            break
        else:
            print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")

    # 根據IP地址自動設置系統名稱
    suggested_system_name = f"vc{network_config['ip'].split('.')[-1]}.lenovo.com"
    network_config['system_name'] = input(f"Enter vCenter system name <press Enter to accept {Fore.CYAN}{suggested_system_name}{Style.RESET_ALL}>: ").strip()
    if network_config['system_name'] == "":
        network_config['system_name'] = suggested_system_name
    
    network_config['prefix'] = input(f"Enter vCenter prefix <press Enter to accept default {Fore.CYAN}{default_VC_prefix}{Style.RESET_ALL}>: ").strip()
    if network_config['prefix'] == "":
        network_config['prefix'] = default_VC_prefix
    
    while True:
        network_config['gateway'] = input(f"Enter vCenter gateway <press Enter to accept default {Fore.CYAN}{default_VC_gateway}{Style.RESET_ALL}>: ").strip()
        if network_config['gateway'] == "":
            network_config['gateway'] = default_VC_gateway
        if validate_ip(network_config['gateway']):
            break
        else:
            print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")
    
    while True:
        dns_servers = input(f"Enter vCenter DNS server <press Enter to accept default {Fore.CYAN}{default_VC_dns_servers}{Style.RESET_ALL}>: ").strip()
        if dns_servers == "":
            dns_servers = default_VC_dns_servers
        if validate_ip(dns_servers):
            break
        else:
            print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")
    network_config['dns_servers'] = [server.strip() for server in dns_servers.split(',')]

    deployment_network = input(f"Enter vCenter deployment network <press Enter to accept default {Fore.CYAN}{default_VC_deployment_network}{Style.RESET_ALL}>: ").strip()
    if deployment_network == "":
        deployment_network = default_VC_deployment_network

    
    # 設置密碼
    root_password = input(f"Enter vCenter root password <press Enter to accept default {Fore.CYAN}{default_VC_root_password}{Style.RESET_ALL}>: ").strip()
    if root_password == "":
        root_password = default_VC_root_password
    sso_password = input(f"Enter vCenter SSO password <press Enter to accept default {Fore.CYAN}{default_VC_sso_password}{Style.RESET_ALL}>: ").strip()
    if sso_password == "":
        sso_password = default_VC_sso_password
    
    # 部署大小
    deployment_size = "medium"
    
    # 臨時文件路徑
    template_path = os.path.join(os.getcwd(), "vcsa_deployment.json")
    
    mount_drive = None
    deployment_success = False
    try:
        # 掛載ISO
        print("\n\nMounting VCSA ISO...")
        print(f"vCenter ISO file: {iso_path}")
        mount_drive = mount_iso(iso_path)
        print(f"Mounted drive: {mount_drive}")
        
        # 獲取vcsa-deploy工具路徑
        vcsa_deploy_path = get_vcsa_deploy_path(mount_drive)

        
        # 創建部署模板
        print("Creating deployment template...")
        template = create_json_template(esxi_host, esxi_username, esxi_password, template_path, vm_name, deployment_network)
        
        # 修改模板中的網路配置
        with open(template_path, 'r') as f:
            config = json.load(f)
        
        # 更新網路配置
        config['new_vcsa']['network']['ip'] = network_config['ip']
        config['new_vcsa']['network']['prefix'] = network_config['prefix']
        config['new_vcsa']['network']['gateway'] = network_config['gateway']
        config['new_vcsa']['network']['dns_servers'] = network_config['dns_servers']
        config['new_vcsa']['network']['system_name'] = network_config['system_name']
        
        # 更新密碼和部署大小
        config['new_vcsa']['os']['password'] = root_password
        config['new_vcsa']['sso']['password'] = sso_password
        config['new_vcsa']['appliance']['deployment_option'] = deployment_size
        
        # 保存更新後的配置
        with open(template_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"{Fore.GREEN}Deployment template saved to: {template_path}{Style.RESET_ALL}\n\n")
        
        # 確認部署
        while True:
            confirmation = input("Are you ready to deploy vCenter to TC? (y/n): ").strip().lower()
            if confirmation in ['y', 'n']:
                break
        
        if confirmation == 'y':
            # 部署vCenter
            deployment_success = deploy_vcenter(vcsa_deploy_path, template_path)
        else:
            print("Deployment canceled")
    
    except Exception as e:
        print(f"Error: {e}")
        deployment_success = False
    
    finally:
        # 清理：卸載ISO
        if mount_drive:
            print("\n\nUnmounting ISO...")
            unmount_iso(mount_drive, iso_path)

        # if os.path.exists(template_path):
        #     try:
        #         os.remove(template_path)
        #         print(f"已删除臨時文件: {template_path}")
        #     except:
        #         pass
        
        # 只有在部署成功時才顯示成功信息
        if deployment_success:
            print(f"\n\n{Fore.GREEN}***************************************{Style.RESET_ALL}")
            print(f"{Fore.GREEN}All configurations have been completed!{Style.RESET_ALL}")
            
            url_management = f"https://{network_config['system_name']}:5480"
            url_vcsa = f"https://{network_config['system_name']}"
            pyperclip.copy(url_management)
            print(f"\nEnsure the jump server switched to the vCenter network (192.168.x.x), then open your browser to visit the following URLs:")
            print(f"\n   - vCenter Server Management UI: {Fore.CYAN}{url_management}{Style.RESET_ALL}")
            print(f"\n   - vCenter Client UI: {Fore.CYAN}{url_vcsa}{Style.RESET_ALL}")
            print(f"\nLogin with user name: {Fore.CYAN}administrator@vsphere.local{Style.RESET_ALL} and password: {Fore.CYAN}{sso_password}{Style.RESET_ALL}")

        
        input(f"\n\n{Fore.LIGHTBLACK_EX}<press Enter to return to the main menu...>{Style.RESET_ALL}")

if __name__ == "__main__":
    main()




# Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false

# VC_ip = "192.168.4.99"
# VC_user = "administrator@vsphere.local"
# VC_password = "Admin!23"

# f"Connect-VIServer -Server '{VC_ip}' -User '{VC_user}' -Password '{VC_password}' -Force" 
# Get-VirtualPortGroup | Select-Object -ExpandProperty Name　取得網路介面


