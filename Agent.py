#!/usr/bin/env python3

import os
import re
import sys
import subprocess
from typing import Optional
import paramiko
from colorama import init, Fore, Style
import time
import pyperclip

# Initialize colorama
init()


# User-defined settings
external_gateway = "192.168.4.7" 
external_dns = "10.241.96.14"
internal_gateway = "192.168.4.1"
internal_dnf = "192.168.4.1"
username = "root"
password = "vmware"


# 檢查IP格式
def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(ip_pattern, ip) is not None and \
           all(0 <= int(part) <= 255 for part in ip.split('.'))

# 檢查IP是否Ping通
def ping_check(ip: str) -> bool:
    """Check if IP is reachable"""
    try:
        # Modified for Windows compatibility
        param = '-n' if os.name == 'nt' else '-c'
        # 減少 ping 次數到 1 次，並設定較短的超時時間
        result = subprocess.run(['ping', param, '1', '-w', '1', ip], 
                              capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False

# 檢查Internet連線
def check_internet(ssh) -> bool:
    """Check internet connectivity"""
    print("\nVerifying Internet connectivity...")
    try:

        cmd = 'wget --spider --timeout=5 www.google.com'
        stdin, stdout, stderr = ssh.exec_command(cmd)
        
        # 獲取命令執行狀態
        exit_status = stdout.channel.recv_exit_status()
        
        if exit_status == 0:
            return True
        else:
            error = stderr.read().decode()
            print(f"{Fore.RED}Network check failed with error: {error}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}Error checking internet connection: {str(e)}{Style.RESET_ALL}")
        return False

# 建立SSH連線
def ssh_connect(hostname: str, username: str, password: str, key_path: Optional[str] = None):
    """Establish SSH connection"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # 如果提供了密鑰路徑，使用密鑰認證
        if key_path and os.path.exists(key_path):
            client.connect(
                hostname, 
                username=username, 
                key_filename=key_path
            )
        else:
            # 如果沒有提供密鑰路徑，使用密碼認證
            client.connect(
                hostname, 
                username=username, 
                password=password
            )
        return client
    except Exception as e:
        print(f"{Fore.RED}SSH Connection Error: {e}{Style.RESET_ALL}")
        return None


# 配置hosts檔案
def configure_hosts_file(ssh_client, internal_ip: str) -> bool:
    """Configure /etc/hosts file on VIVa"""
    try:
        # 檢查是否已存在IP
        stdin, stdout, stderr = ssh_client.exec_command(
            f"grep -q '{internal_ip} cert-viva-local' /etc/hosts"
        )
        if stdout.channel.recv_exit_status() != 0:
            # 在"# End"行之前新增IP
            command = f"""sudo sed -i '/# End/i {internal_ip} cert-viva-local' /etc/hosts"""
            stdin, stdout, stderr = ssh_client.exec_command(command)
            if stdout.channel.recv_exit_status() != 0:
                print(f"{Fore.RED}Failed to modify /etc/hosts{Style.RESET_ALL}")
                return False
        return True
    except Exception as e:
        print(f"{Fore.RED}Error configuring hosts file: {e}{Style.RESET_ALL}")
        return False


# 配置外部網路設定
def configure_external_network_config(ssh_client, external_ip: str, external_gateway: str, external_dns: str) -> bool:
    """Configure network settings"""
    network_config = f"""[Match]
Name=e*

[Network]
DHCP=no
Address={external_ip}/22
Gateway={external_gateway}
DNS={external_dns}
"""
    try:
        # 寫入網路設定
        print("\nConfiguring /etc/systemd/network/99-dhcp-en.network for external network...")
        sftp = ssh_client.open_sftp()
        with sftp.file('/etc/systemd/network/99-dhcp-en.network', 'w') as f:
            f.write(network_config)
        sftp.close()
        
        # 重新啟動網路服務
        stdin, stdout, stderr = ssh_client.exec_command(
            "sudo systemctl restart systemd-networkd"
        )
        
        # 關閉現有連線，因為它會斷開
        ssh_client.close()
        
        # 等待系統重新啟動網路服務
        print("Waiting for network service to restart...")
        time.sleep(10)  # 等待10秒讓網路服務重啟完成
        
        # 使用新的IP重新建立SSH連線
        new_ssh_client = ssh_connect(external_ip, username, password)
        if new_ssh_client:
            return True, new_ssh_client
        return False, None
    except Exception as e:
        print(f"{Fore.RED}External network configuration error: {e}{Style.RESET_ALL}")
        return False, None

# 設定主機名稱
def set_hostname(ssh_client) -> bool:
    """Set hostname to photon-viva"""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(
            "hostnamectl set-hostname photon-viva"
        )
        if stdout.channel.recv_exit_status() != 0:
            print(f"{Fore.RED}Failed to set hostname{Style.RESET_ALL}")
            return False
        return True
    except Exception as e:
        print(f"{Fore.RED}Error setting hostname: {e}{Style.RESET_ALL}")
        return False

def configure_internal_network_config(ssh_client, internal_ip: str, internal_gateway: str, internal_dns: str) -> bool:
    """Configure internal network settings"""
    network_config = f"""[Match]
Name=e*

[Network]
DHCP=no
Address={internal_ip}/22
Gateway={internal_gateway}
DNS={internal_dns}
IP6AcceptRA=no

[DHCPv4]
SendRelease=no
"""
    try:
        # 寫入網路設定
        print("\nConfiguring /etc/systemd/network/99-dhcp-en.network for internal network...")
        sftp = ssh_client.open_sftp()
        with sftp.file('/etc/systemd/network/99-dhcp-en.network', 'w') as f:
            f.write(network_config)
        sftp.close()
        
        # 重新啟動網路服務
        stdin, stdout, stderr = ssh_client.exec_command(
            "sudo systemctl restart systemd-networkd"
        )
        
        # 關閉現有連線，因為它會斷開
        ssh_client.close()
        
        # 等待系統重新啟動網路服務
        print("Waiting for network service to restart...")
        time.sleep(10)  # 等待10秒讓網路服務重啟完成
        
        # 使用新的IP重新建立SSH連線
        new_ssh_client = ssh_connect(internal_ip, username, password)
        if new_ssh_client:
            return True, new_ssh_client
        return False, None
    except Exception as e:
        print(f"{Fore.RED}Internal network configuration error: {e}{Style.RESET_ALL}")
        return False, None


def main():
    # 輸入內部IP
    while True:
        internal_ip = input("Enter VIVa IP address: ").strip()
        if validate_ip(internal_ip):
            if ping_check(internal_ip):
                break
            else:
                print(f"{Fore.RED}Failed to ping IP{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")

    # 建立SSH連線
    ssh_client = ssh_connect(internal_ip, username, password)
    if not ssh_client:
        sys.exit(1)


    # 更改主機名稱
    print(f"\nSetting hostname to photon-viva...")
    if not set_hostname(ssh_client):
        ssh_client.close()
        sys.exit(1)
    print(f"{Fore.GREEN}Hostname configuration successful{Style.RESET_ALL}\n")


    # 配置hosts檔案
    print(f"\nConfiguring /etc/hosts...")
    if not configure_hosts_file(ssh_client, internal_ip):
        ssh_client.close()
        sys.exit(1)
    print(f"{Fore.GREEN}Hosts file configuration successful{Style.RESET_ALL}\n\n")

    # 輸入外部IP並在配置前檢查
    while True:
        external_ip = input("Enter IP address (for Internet access): ").strip()
        if not validate_ip(external_ip):
            print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")
            continue
        
        # 只在配置前檢查IP是否被使用
        if ping_check(external_ip):
            print(f"{Fore.YELLOW}IP {external_ip} is already in use. Please choose another IP{Style.RESET_ALL}")
            continue
        
        # IP有效且未被使用，跳出循環進行配置
        break

    # 配置外部網路設定 (不再檢查IP)
    success, new_ssh_client = configure_external_network_config(ssh_client, external_ip, external_gateway, external_dns)
    if success and new_ssh_client:
        print(f"{Fore.GREEN}External network configuration successful{Style.RESET_ALL}\n")
        ssh_client = new_ssh_client  # 使用新的SSH連線
        
        # 驗證網路連線成功才繼續
        if check_internet(ssh_client):
            print(f"{Fore.GREEN}Internet connectivity check successful{Style.RESET_ALL}\n\n")

            # 更新Agent並下載cert docker image
            print("Refreshing VIVA service...")
            stdin, stdout, stderr = ssh_client.exec_command(
                "AgentLanucher -i"
            )
            if stdout.channel.recv_exit_status() == 0:
                print(f"{Fore.GREEN}VIVA service refresh successful{Style.RESET_ALL}\n")
                
                # 配置內部網路設定
                success, new_ssh_client = configure_internal_network_config(
                    ssh_client, internal_ip, internal_gateway, internal_dnf
                )
                if success and new_ssh_client:
                    print(f"{Fore.GREEN}Internal network configuration successful{Style.RESET_ALL}\n")
                    ssh_client = new_ssh_client
                    
                    # 關閉SSH連線
                    ssh_client.close()
                    
                else:
                    print(f"{Fore.RED}Internal network configuration failed{Style.RESET_ALL}\n")
            else:
                print(f"{Fore.RED}Failed to refresh VIVa service{Style.RESET_ALL}\n")
                
            # 顯示成功完成訊息
            print(f"\n\n\n{Fore.GREEN}***************************************{Style.RESET_ALL}")
            print(f"{Fore.GREEN}All configurations have been completed!{Style.RESET_ALL}")
            
            # 當顯示訊息時，同時複製網址到剪貼簿
            url = "http://cert-viva-local/Certs"
            pyperclip.copy(url)
            print(f"\nEnsure the jump server has Internet connectivity, then open your browser to visit {url}.")
            print(f"(URL has been copied to clipboard)")
            
        else:
            print(f"{Fore.RED}Internet connectivity check failed{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.RED}Network configuration failed{Style.RESET_ALL}\n")

    # 等待使用者按鍵
    input("")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)