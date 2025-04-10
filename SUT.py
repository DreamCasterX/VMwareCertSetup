#!/usr/bin/env python3

import os
import re
import sys
import subprocess
from typing import Optional
import paramiko
from colorama import init, Fore, Style
import time

# Initialize colorama
init()


# User-defined settings for SUT
SUT_username = "root"
SUT_password = "Admin!23"
default_submask = "255.255.252.0"
default_gateway = "192.168.4.1"
default_dns = "192.168.4.1"


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


def configure_network(ssh_client, new_ip, subnet_mask, gateway):
    """設定ESXi的網路設定"""
    try:
        # 設定靜態IP
        cmd = f'esxcli network ip interface ipv4 set -i vmk0 -t static -I {new_ip} -N {subnet_mask} -g {gateway}'
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        if stderr.channel.recv_exit_status() == 0:
            return True
        else:
            print(f"{Fore.RED}Failed to set network configuration{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}Error setting network configuration: {e}{Style.RESET_ALL}")
        return False

def configure_dns(ssh_client, primary_dns, hostname):
    """設定ESXi的DNS設定"""
    try:
        # 清除現有的 DNS servers
        stdin, stdout, stderr = ssh_client.exec_command('esxcli network ip dns server remove --all')
        if stderr.channel.recv_exit_status() != 0:
            print(f"{Fore.RED}Failed to clear existing DNS servers{Style.RESET_ALL}")
            return False

        # 設定 Primary DNS server IP
        stdin, stdout, stderr = ssh_client.exec_command(f'esxcli network ip dns server add -s {primary_dns}')
        if stderr.channel.recv_exit_status() != 0:
            print(f"{Fore.RED}Failed to set Primary DNS server{Style.RESET_ALL}")
            return False


        # 設定 DNS hostname (FQDN)
        stdin, stdout, stderr = ssh_client.exec_command(f'esxcli system hostname set --fqdn {hostname}')
        if stderr.channel.recv_exit_status() == 0:
            return True
        else:
            print(f"{Fore.RED}Failed to set DNS hostname{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}Error setting DNS: {e}{Style.RESET_ALL}")
        return False

# def enable_ssh_services(ssh_client):
#     """啟用SSH服務"""
#     try:
#         commands = [
#             'vim-cmd hostsvc/enable_ssh',
#             'vim-cmd hostsvc/start_ssh'
#         ]
#         for cmd in commands:
#             stdin, stdout, stderr = ssh_client.exec_command(cmd)
#             if stderr.channel.recv_exit_status() != 0:
#                 print(f"{Fore.RED}執行命令失敗: {cmd}{Style.RESET_ALL}")
#                 return False
#         print(f"{Fore.GREEN}SSH enabled successfully{Style.RESET_ALL}")
#         return True
#     except Exception as e:
#         print(f"{Fore.RED}啟用服務時發生錯誤: {e}{Style.RESET_ALL}")
#         return False

def configure_firewall(ssh_client):
    """根據VMware版本設定防火牆"""
    try:
        # 取得VMware版本
        stdin, stdout, stderr = ssh_client.exec_command("vmware -r | awk -F ' ' '{print $3}' | cut -d '.' -f1")
        version = stdout.read().decode().strip()
        
        if version == '9':
            cmd = 'esxcli network firewall set --enabled false'
        elif version == '8':
            cmd = '''esxcli network firewall set --enabled false
                    esxcli system wbem set -e 0
                    esxcli system wbem set -e 1
                    esxcli hardware trustedboot get'''
        else:
            print(f"{Fore.YELLOW}不支援的VMware版本: {version}{Style.RESET_ALL}")
            return False

        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        if stderr.channel.recv_exit_status() == 0:
            print(f"{Fore.GREEN}Firewall configured successfully{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}Failed to configure firewall{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}Error configuring firewall: {e}{Style.RESET_ALL}")
        return False

def enable_shell(ssh_client):
    """啟用 ESXi Shell"""
    try:
        # 啟用 ESXi Shell
        stdin, stdout, stderr = ssh_client.exec_command('vim-cmd hostsvc/enable_esx_shell')
        if stderr.channel.recv_exit_status() != 0:
            print(f"{Fore.RED}啟用 ESXi Shell 失敗{Style.RESET_ALL}")
            return False

        # 啟動 ESXi Shell
        stdin, stdout, stderr = ssh_client.exec_command('vim-cmd hostsvc/start_esx_shell')
        if stderr.channel.recv_exit_status() != 0:
            print(f"{Fore.RED}啟動 ESXi Shell 失敗{Style.RESET_ALL}")
            return False

        print(f"{Fore.GREEN}ESXi Shell 已成功啟用{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}啟用 ESXi Shell 時發生錯誤: {e}{Style.RESET_ALL}")
        return False

def display_system_info(ssh_client):
    """顯示ESXi主機系統資訊"""
    try:
        # 定義要執行的命令和對應的標籤
        commands = {
            'Product Name': "esxcli hardware platform get | grep 'Product Name' | awk -F ': ' '{print $2}'",
            'OS version': "vmware -r",
            'Secure Boot state': "python3 /usr/lib/vmware/secureboot/bin/secureBoot.py -s",
            'BMC IP': "esxcli hardware ipmi bmc get | grep 'IPv4Address' | awk -F ': ' '{print $2}'",
            'OS IP': "esxcli network ip interface ipv4 get | awk 'NR==3 {print $2}'",
            'Submask': "esxcli network ip interface ipv4 get | awk 'NR==3 {print $3}'",
            'Gateway': "esxcli network ip interface ipv4 get | awk 'NR==3 {print $6}'",
            'DNS server': "esxcli network ip dns server list | awk -F ': ' '{print $2}'",
            'DNS hostname': "esxcli system hostname get | grep 'Fully Qualified Domain Name' | awk -F ': ' '{print $2}'"
        }

        # 顯示所有資訊
        for label, command in commands.items():
            stdin, stdout, stderr = ssh_client.exec_command(command)
            result = stdout.read().decode().strip()
            print(f"{label}: {Fore.CYAN}{result}{Style.RESET_ALL}")
        
        return True
    except Exception as e:
        print(f"{Fore.RED}Error getting system information: {e}{Style.RESET_ALL}")
        return False

def show_menu():
    print(
    r"""
 =====================================
 VMware Cert Auto Configuration Tool 
                 v1.0 
 =====================================

Please select an option:
1. Configure SUT
2. Configure VIVa
3. Exit

"""
    )
    while True:
        choice = input("Enter your choice (1-3): ").strip()
        if choice in ['1', '2', '3']:
            return choice
        print(f"{Fore.YELLOW}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")

def main():
    while True:
        choice = show_menu()
        
        if choice == '3':
            print("\nExiting...")
            break
            
        try:
            configurator = SUTConfigurator() if choice == '1' else VIVaConfigurator()
            configurator.configure()
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
        except Exception as e:
            print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")
        
        input("\nPress Enter to return to the main menu...")

class BaseConfigurator:
    """基礎設定類別"""
    def __init__(self):
        self.ssh_client = None

    def configure(self):
        """基礎設定流程"""
        try:
            # 取得IP地址
            ip = input("請輸入IP地址: ").strip()
            
            # 驗證IP格式
            if not validate_ip(ip):
                print(f"{Fore.RED}無效的IP地址格式{Style.RESET_ALL}")
                return

            # 檢查IP是否可連線
            if not ping_check(ip):
                print(f"{Fore.RED}無法連線到IP: {ip}{Style.RESET_ALL}")
                return

            # 建立SSH連線
            self.ssh_client = ssh_connect(ip, SUT_username, SUT_password)
            if not self.ssh_client:
                return

            # 啟用ESXi Shell
            if not enable_shell(self.ssh_client):
                return

            # 取得網路設定
            subnet_mask = input("請輸入子網路遮罩 (例如: 255.255.255.0): ").strip()
            gateway = input("請輸入閘道器IP: ").strip()
            
            # 設定網路
            if configure_network(self.ssh_client, ip, subnet_mask, gateway):
                print("網路設定成功。嘗試使用新IP重新連線...")
                self.ssh_client.close()
                time.sleep(5)
                
                self.ssh_client = ssh_connect(ip, SUT_username, SUT_password)
                if not self.ssh_client:
                    print(f"{Fore.RED}使用新IP重新連線失敗{Style.RESET_ALL}")
                    return

            # 取得DNS設定
            primary_dns = input("請輸入主要DNS IP: ").strip()
            hostname = input("請輸入DNS主機名稱: ").strip()
            
            # 設定DNS
            if not configure_dns(self.ssh_client, primary_dns, hostname):
                return

            # 設定防火牆
            if not configure_firewall(self.ssh_client):
                return

            print(f"{Fore.GREEN}所有設定都已完成！{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}設定過程中發生錯誤: {e}{Style.RESET_ALL}")
        finally:
            if self.ssh_client:
                self.ssh_client.close()

class SUTConfigurator(BaseConfigurator):
    """SUT設定類別"""
    pass

class VIVaConfigurator(BaseConfigurator):
    """VIVa設定類別"""
    pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)