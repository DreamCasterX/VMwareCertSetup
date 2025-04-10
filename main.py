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
from abc import ABC, abstractmethod

# Initialize colorama
init()

# 基礎配置器類別
class BaseConfigurator(ABC):
    # 初始化SSH連接
    def __init__(self):
        self.ssh_client = None

    # 驗證IP地址格式
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return re.match(ip_pattern, ip) is not None and \
               all(0 <= int(part) <= 255 for part in ip.split('.'))

    # 檢查IP是否可達
    def ping_check(self, ip: str) -> bool:
        """Check if IP is reachable"""
        try:
            param = '-n' if os.name == 'nt' else '-c'
            result = subprocess.run(['ping', param, '1', '-w', '1', ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False

    # 建立SSH連接
    def ssh_connect(self, hostname: str, username: str, password: str, key_path: Optional[str] = None):
        """Establish SSH connection"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if key_path and os.path.exists(key_path):
                client.connect(hostname, username=username, key_filename=key_path)
            else:
                client.connect(hostname, username=username, password=password)
            return client
        except Exception as e:
            print(f"{Fore.RED}SSH Connection Error: {e}{Style.RESET_ALL}")
            return None

    # 主配置方法
    @abstractmethod
    def configure(self):
        """主配置方法，由子類別實作"""
        pass

    # 基礎網路配置方法
    @abstractmethod
    def configure_network(self, ssh_client, new_ip, subnet_mask, gateway):
        """基礎網路配置方法，由子類別實作"""
        raise NotImplementedError("Subclasses must implement this method")  

# SUT配置器類別
class SUTConfigurator(BaseConfigurator):
    def __init__(self):
        super().__init__()
        self.username = "root"
        self.password = "Admin!23"
        self.default_submask = "255.255.252.0"
        self.default_gateway = "192.168.4.1"
        self.default_dns = "192.168.4.1"

    # SUT特定網路配置   
    def configure_network(self, ssh_client, new_ip, subnet_mask, gateway):
        """SUT specific network configuration"""
        try:
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

    # 配置ESXi DNS設定
    def configure_dns(self, ssh_client, primary_dns, hostname):
        """Configure ESXi DNS settings"""
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


    # 配置防火牆
    def configure_firewall(self, ssh_client):
        """根據VMware版本設定防火牆"""
        try:
            # Get VMware version
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
                print(f"{Fore.YELLOW}Unsupported VMware version: {version}{Style.RESET_ALL}")
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
    
    def enable_shell(self, ssh_client):
        """啟用 ESXi Shell"""
        try:
            commands = [
                'vim-cmd hostsvc/enable_esx_shell',
                'vim-cmd hostsvc/start_esx_shell'
            ]
            for cmd in commands:
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                if stderr.channel.recv_exit_status() != 0:
                    return False

            print(f"{Fore.GREEN}ESXi Shell enabled successfully{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}Error enabling ESXi Shell: {e}{Style.RESET_ALL}")
            return False

    def display_system_info(self, ssh_client):
        """顯示 ESXi 主機系統資訊"""
        try:
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

            for label, command in commands.items():
                stdin, stdout, stderr = ssh_client.exec_command(command)
                result = stdout.read().decode().strip()
                print(f"{label}: {Fore.YELLOW}{result}{Style.RESET_ALL}")
            
            return True
        except Exception as e:
            print(f"{Fore.RED}Error getting system information: {e}{Style.RESET_ALL}")
            return False

    def configure(self):
        print(
        f"""{Fore.CYAN}
 ___________________________________________________________________
 Now configuring SUT...
 To move forward, make sure you've already completed the following:
    (1) Installed VMware ESXi on SUT
    (2) Enabled SSH access on SUT
    (3) Obtained the DHCP IP address of SUT
 ___________________________________________________________________{Style.RESET_ALL}
    """
        )

        # 獲取 SUT IP
        while True:
            SUT_dhcp_ip = input("Enter SUT IP address: ").strip()
            if self.validate_ip(SUT_dhcp_ip):
                if self.ping_check(SUT_dhcp_ip):
                    break
                else:
                    print(f"{Fore.RED}Failed to ping IP{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")

        # 建立 SSH 連接
        ssh_client = self.ssh_connect(SUT_dhcp_ip, self.username, self.password)
        if not ssh_client:
            return

        # 啟用 ESXi Shell
        print("\nEnabling ESXi Shell...")
        if not self.enable_shell(ssh_client):
            print(f"{Fore.RED}Failed to enable ESXi Shell{Style.RESET_ALL}")
            ssh_client.close()
            return

        # 顯示當前系統資訊
        print("\n\nGetting the current system information...")
        print("-----------------------------------------")
        self.display_system_info(ssh_client)

        # 獲取網路配置詳細資訊
        print("\n")
        while True:
            static_ip = input("Set a new IP: ").strip()
            if not self.validate_ip(static_ip):
                print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")
                continue
                
            if self.ping_check(static_ip):
                # 如果IP已被使用，則提示用戶選擇另一個IP
                print(f"{Fore.RED}IP {static_ip} is already in use. Please choose another IP.{Style.RESET_ALL}")
                continue
            break

        # 設定子網掩碼
        while True:
            subnet_mask = input(f"Set Subnet mask <press Enter to accept default {Fore.CYAN}{self.default_submask}{Style.RESET_ALL}>: ").strip()
            if subnet_mask == "":
                subnet_mask = self.default_submask
            if not self.validate_ip(subnet_mask):
                print(f"{Fore.YELLOW}Invalid netmask format{Style.RESET_ALL}")
                continue
            break

        # 設定預設閘道
        while True:
            gateway = input(f"Set default Gateway <press Enter to accept default {Fore.CYAN}{self.default_gateway}{Style.RESET_ALL}>: ").strip()
            if gateway == "":
                gateway = self.default_gateway
            if not self.validate_ip(gateway):
                print(f"{Fore.YELLOW}Invalid gateway format{Style.RESET_ALL}")
                continue
            break

        # 配置網路
        print("\nConfiguring IP settings...")
        if self.configure_network(ssh_client, static_ip, subnet_mask, gateway):
            print(f"{Fore.GREEN}Network configuration successful{Style.RESET_ALL}")
            ssh_client.close()
            time.sleep(5)  # Wait for network changes to take effect
            
            # 嘗試重新連接新IP
            ssh_client = self.ssh_connect(static_ip, self.username, self.password)
            if not ssh_client:
                print(f"{Fore.RED}Failed to reconnect with new IP{Style.RESET_ALL}")
                return

        # 獲取 DNS 配置詳細資訊
        print("\n")
        while True:
            primary_dns = input(f"Set primary DNS <press Enter to accept default {Fore.CYAN}{self.default_dns}{Style.RESET_ALL}>: ").strip()
            if primary_dns == "":
                primary_dns = self.default_dns
            if not self.validate_ip(primary_dns):
                print(f"{Fore.YELLOW}Invalid DNS IP format{Style.RESET_ALL}")
                continue
            break
        
        # 從 static_ip 提取最後一組數字作為預設DNS hostname名稱
        last_octet = static_ip.split('.')[-1]
        default_hostname = f"esxi{last_octet}"
        
        # 從用戶獲取 DNS hostname
        dns_hostname = input(f"Set DNS hostname <press Enter to accept default {Fore.CYAN}{default_hostname}{Style.RESET_ALL}>: ").strip()
        if dns_hostname == "":
            dns_hostname = default_hostname

        # 配置 DNS 和 DNS hostname
        print("\nConfiguring DNS settings...")
        if not self.configure_dns(ssh_client, primary_dns, dns_hostname):
            return
        print(f"{Fore.GREEN}DNS IP and hostname set successfully{Style.RESET_ALL}")

        # 配置防火牆
        print("\nConfiguring firewall...")
        if not self.configure_firewall(ssh_client):
            return

        # 顯示更新後的系統資訊
        print("\nGetting the updated system information...")
        print("-----------------------------------------")
        self.display_system_info(ssh_client)
        ssh_client.close()

        print(f"\n\n\n{Fore.GREEN}***************************************{Style.RESET_ALL}")
        print(f"{Fore.GREEN}All configurations have been completed!{Style.RESET_ALL}")
        print(f"\nRemember to create a new host {Fore.YELLOW}{dns_hostname}{Style.RESET_ALL} with IP {Fore.YELLOW}{static_ip}{Style.RESET_ALL} on DHCP server.")

class VIVaConfigurator(BaseConfigurator):
    def __init__(self):
        super().__init__()
        self.username = "root"
        self.password = "vmware"
        self.external_gateway = "192.168.4.7"
        self.external_dns = "10.241.96.14"
        self.internal_gateway = "192.168.4.1"
        self.internal_dns = "192.168.4.1"

    def check_internet(self, ssh) -> bool:
        """Check internet connectivity"""
        print("\nVerifying Internet connectivity...")
        try:
            cmd = 'wget --spider --timeout=5 www.google.com'
            stdin, stdout, stderr = ssh.exec_command(cmd)
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

    def configure_hosts_file(self, ssh_client, internal_ip: str) -> bool:
        """Configure /etc/hosts file on VIVa"""
        try:
            stdin, stdout, stderr = ssh_client.exec_command(
                f"grep -q '{internal_ip} cert-viva-local' /etc/hosts"
            )
            if stdout.channel.recv_exit_status() != 0:
                command = f"""sudo sed -i '/# End/i {internal_ip} cert-viva-local' /etc/hosts"""
                stdin, stdout, stderr = ssh_client.exec_command(command)
                if stdout.channel.recv_exit_status() != 0:
                    print(f"{Fore.RED}Failed to modify /etc/hosts{Style.RESET_ALL}")
                    return False
            return True
        except Exception as e:
            print(f"{Fore.RED}Error configuring hosts file: {e}{Style.RESET_ALL}")
            return False

    def configure_external_network_config(self, ssh_client, external_ip: str) -> tuple:
        """Configure external network settings"""
        network_config = f"""[Match]
Name=e*

[Network]
DHCP=no
Address={external_ip}/22
Gateway={self.external_gateway}
DNS={self.external_dns}
IP6AcceptRA=no

[DHCPv4]
SendRelease=no
"""
        try:
            print("\nConfiguring /etc/systemd/network/99-dhcp-en.network for external network...")
            sftp = ssh_client.open_sftp()
            with sftp.file('/etc/systemd/network/99-dhcp-en.network', 'w') as f:
                f.write(network_config)
            sftp.close()
            
            stdin, stdout, stderr = ssh_client.exec_command(
                "sudo systemctl restart systemd-networkd"
            )
            
            ssh_client.close()
            
            print("Waiting for network service to restart...")
            time.sleep(10)
            
            new_ssh_client = self.ssh_connect(external_ip, self.username, self.password)
            if new_ssh_client:
                return True, new_ssh_client
            return False, None
        except Exception as e:
            print(f"{Fore.RED}External network configuration error: {e}{Style.RESET_ALL}")
            return False, None

    def set_hostname(self, ssh_client) -> bool:
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

    def configure_internal_network_config(self, ssh_client, internal_ip: str) -> tuple:
        """Configure internal network settings"""
        network_config = f"""[Match]
Name=e*

[Network]
DHCP=no
Address={internal_ip}/22
Gateway={self.internal_gateway}
DNS={self.internal_dns}
IP6AcceptRA=no

[DHCPv4]
SendRelease=no
"""
        try:
            print("\nConfiguring /etc/systemd/network/99-dhcp-en.network for internal network...")
            sftp = ssh_client.open_sftp()
            with sftp.file('/etc/systemd/network/99-dhcp-en.network', 'w') as f:
                f.write(network_config)
            sftp.close()
            
            stdin, stdout, stderr = ssh_client.exec_command(
                "sudo systemctl restart systemd-networkd"
            )
            
            ssh_client.close()
            
            print("Waiting for network service to restart...")
            time.sleep(10)
            
            new_ssh_client = self.ssh_connect(internal_ip, self.username, self.password)
            if new_ssh_client:
                return True, new_ssh_client
            return False, None
        except Exception as e:
            print(f"{Fore.RED}Internal network configuration error: {e}{Style.RESET_ALL}")
            return False, None

    def update_jump_server_hosts_file(self, internal_ip: str) -> bool:
        """Update local hosts file with VIVa entry"""
        hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
        new_entry = f"{internal_ip} cert-viva-local"
        
        try:
            print(f"\nUpdating {hosts_file} for jump server")
            
            with open(hosts_file, 'r') as f:
                lines = f.readlines()
            
            filtered_lines = [line for line in lines if 'cert-viva-local' not in line]
            
            with open(hosts_file, 'w') as f:
                f.writelines(filtered_lines)
                f.write(f"\n{new_entry}")
            return True
        except PermissionError:
            print(f"{Fore.RED}Permission denied. Please run the script as administrator{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}Error updating hosts file: {e}{Style.RESET_ALL}")
            return False

    def configure_network(self, ssh_client, new_ip, subnet_mask, gateway):
        """VIVa specific network configuration"""
        # VIVa specific implementation
        pass

    def configure(self):
        print(
        f"""{Fore.CYAN}
 ___________________________________________________________________
 Now configuring VIVa...
 To move forward, make sure you've already completed the following:
    (1) Downloaded the 'viva-xxxx.ova' from Broadcom TAP website
    (2) Deployed the 'viva-xxxx.ova' on TC
    (3) Obtained the DHCP IP address of VIVa from TC
 ___________________________________________________________________{Style.RESET_ALL}
    """
        )

        # 獲取內部 IP
        while True:
            internal_ip = input("Enter VIVa IP address: ").strip()
            if self.validate_ip(internal_ip):
                if self.ping_check(internal_ip):
                    break
                else:
                    print(f"{Fore.RED}Failed to ping IP{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")

        # 建立 SSH 連接
        ssh_client = self.ssh_connect(internal_ip, self.username, self.password)
        if not ssh_client:
            return

        # 設定主機名稱
        print(f"\nSetting hostname to photon-viva...")
        if not self.set_hostname(ssh_client):
            ssh_client.close()
            return
        print(f"{Fore.GREEN}Hostname configuration successful{Style.RESET_ALL}\n")

        # 配置 hosts 檔案
        print(f"\nConfiguring /etc/hosts...")
        if not self.configure_hosts_file(ssh_client, internal_ip):
            ssh_client.close()
            return
        print(f"{Fore.GREEN}Hosts file configuration successful{Style.RESET_ALL}\n\n")

        # 獲取外部 IP
        while True:
            external_ip = input("Enter IP address (for Internet access): ").strip()
            if not self.validate_ip(external_ip):
                print(f"{Fore.YELLOW}Invalid IP format{Style.RESET_ALL}")
                continue
            
            if self.ping_check(external_ip):
                print(f"{Fore.YELLOW}IP {external_ip} is already in use. Please choose another IP{Style.RESET_ALL}")
                continue
            break

        # 配置外部網路
        success, new_ssh_client = self.configure_external_network_config(ssh_client, external_ip)
        if success and new_ssh_client:
            print(f"{Fore.GREEN}External network configuration successful{Style.RESET_ALL}\n")
            ssh_client = new_ssh_client
            
            if self.check_internet(ssh_client):
                print(f"{Fore.GREEN}Internet connectivity check successful{Style.RESET_ALL}\n\n")

                print("Refreshing VIVA service...")
                stdin, stdout, stderr = ssh_client.exec_command(
                    "bash /opt/broadcom/viva/refresh_viva_service.sh"
                )
                if stdout.channel.recv_exit_status() == 0:
                    print(f"{Fore.GREEN}VIVA service refresh successful{Style.RESET_ALL}\n")
                    
                    success, new_ssh_client = self.configure_internal_network_config(
                        ssh_client, internal_ip
                    )
                    if success and new_ssh_client:
                        print(f"{Fore.GREEN}Internal network configuration successful{Style.RESET_ALL}\n")
                        ssh_client = new_ssh_client
                        
                        ssh_client.close()
                        
                        if self.update_jump_server_hosts_file(internal_ip):
                            print(f"{Fore.GREEN}Jump server hosts file configuration successful{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.RED}Failed to update jump server hosts file{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Internal network configuration failed{Style.RESET_ALL}\n")
                else:
                    print(f"{Fore.RED}Failed to refresh VIVa service{Style.RESET_ALL}\n")
                    
                print(f"\n\n\n{Fore.GREEN}***************************************{Style.RESET_ALL}")
                print(f"{Fore.GREEN}All configurations have been completed!{Style.RESET_ALL}")
                
                url = "http://cert-viva-local/Certs"
                pyperclip.copy(url)
                print(f"\nEnsure the jump server has Internet connectivity, then open your browser to visit {url}.")
                print(f"(URL has been copied to clipboard)")
            else:
                print(f"{Fore.RED}Internet connectivity check failed{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Network configuration failed{Style.RESET_ALL}\n")

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
        
        input("\n[press Enter to return to the main menu...]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)