from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl
from colorama import init, Fore, Style


# Initialize colorama
init()


def add_vm_options(si, vm_name):
    try:
        content = si.RetrieveContent()
        
        # 找到虛擬機
        vm = None
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        for managed_object in container.view:
            if managed_object.name == vm_name:
                vm = managed_object
                break
        container.Destroy()
        
        if not vm:
            print(f"{Fore.RED}VM name: '{vm_name}' is not found{Style.RESET_ALL}")
            return

        # 找到主機系統
        host = vm.runtime.host
        
        # 尋找 NVIDIA GPU PCI 設備
        nvidia_device = None
        for pci_dev in host.hardware.pciDevice:
            if "NVIDIA" in pci_dev.vendorName:
                nvidia_device = pci_dev
                print(f"\nFound NVIDIA GPU:")
                print(f"  Device Name: {Fore.LIGHTCYAN_EX}{pci_dev.deviceName}{Style.RESET_ALL}")
                print(f"  Vendor Name: {Fore.LIGHTCYAN_EX}{pci_dev.vendorName}{Style.RESET_ALL}")
                print(f"  Device ID: {Fore.LIGHTCYAN_EX}{hex(pci_dev.deviceId)}{Style.RESET_ALL}")
                print(f"  Vendor ID: {Fore.LIGHTCYAN_EX}{hex(pci_dev.vendorId)}{Style.RESET_ALL}")
                print(f"  PCI ID: {Fore.LIGHTCYAN_EX}{pci_dev.id}{Style.RESET_ALL}\n")
                break
        
        if not nvidia_device:
            print(f"{Fore.RED}No NVIDIA GPU found on the host{Style.RESET_ALL}")
            return

        # 啟用 PCI 設備的 passthrough
        passthru_sys = host.configManager.pciPassthruSystem
        if passthru_sys:
            # 創建 passthrough 配置
            config = vim.host.PciPassthruConfig()
            config.id = nvidia_device.id
            config.passthruEnabled = True
            
            try:
                # 更新 PCI passthrough 配置
                passthru_sys.UpdatePassthruConfig([config])
                print(f"{Fore.GREEN}Successfully updated PCI passthrough configuration{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Failed to update PCI passthrough config: {e}{Style.RESET_ALL}")
                return
        
        try:
            # 創建 VM 配置
            vm_config_spec = vim.vm.ConfigSpec()
            
            # 添加 PCI passthrough 設備
            pci_spec = vim.vm.device.VirtualDeviceSpec()
            pci_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
            
            pci_device = vim.vm.device.VirtualPCIPassthrough()
            pci_device.backing = vim.vm.device.VirtualPCIPassthrough.DeviceBackingInfo()
            pci_device.backing.id = nvidia_device.id
            pci_device.backing.deviceId = hex(nvidia_device.deviceId)[2:].zfill(4)
            pci_device.backing.systemId = host.hardware.systemInfo.uuid
            pci_device.backing.vendorId = nvidia_device.vendorId
            
            # 設置設備的鍵值
            pci_device.key = -1  # 讓 vSphere 自動分配鍵值
            
            pci_spec.device = pci_device
            
            # 更新設備配置列表
            vm_config_spec.deviceChange = [pci_spec]
            
            print(f"\nAttempting to add PCI device to VM {Fore.CYAN}'{vm_name}'{Style.RESET_ALL}...")
            
            # 重新配置 VM
            task = vm.ReconfigVM_Task(spec=vm_config_spec)
            
            # 等待任務完成
            while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                pass
            
            if task.info.state == vim.TaskInfo.State.success:
                print(f"{Fore.GREEN}Successfully added PCI passthrough device to '{vm_name}'{Style.RESET_ALL}")
                
                # 添加 VM 選項
                try:
                    vm_config_spec = vim.vm.ConfigSpec()
                    vm_config_spec.extraConfig = [
                        vim.option.OptionValue(key='pciHole.start', value='2048'),
                        vim.option.OptionValue(key='pciPassthru.use64bitMMIO', value='TRUE'),
                        vim.option.OptionValue(key='pciPassthru.64bitMMIOSizeGB', value='256')
                    ]
                    
                    # 添加記憶體預留鎖定選項
                    vm_config_spec.memoryReservationLockedToMax = True
                    
                    print(f"\nAdding VM options to {Fore.CYAN}'{vm_name}'{Style.RESET_ALL}...")
                    
                    # 重新配置 VM
                    task = vm.ReconfigVM_Task(spec=vm_config_spec)
                    
                    # 等待任務完成
                    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                        pass
                    
                    if task.info.state == vim.TaskInfo.State.success:
                        print(f"{Fore.GREEN}Successfully added VM options to '{vm_name}'{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Failed to add VM options: {task.info.error}{Style.RESET_ALL}")
                        
                except Exception as e:
                    print(f"{Fore.RED}Error adding VM options: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Failed to add PCI passthrough device to VM: {task.info.error}{Style.RESET_ALL}")
                return
                
        except Exception as e:
            print(f"{Fore.RED}Error adding PCI device to VM: {e}{Style.RESET_ALL}")
            return
            
    except Exception as e:
        print(f"{Fore.RED}Error adding VM options: {e}{Style.RESET_ALL}")
        
def get_valid_input(prompt, input_type=str, default=None, min_value=None):
    """獲取有效的用戶輸入
    
    Args:
        prompt: 提示訊息
        input_type: 輸入類型 (str, int)
        default: 默認值
        min_value: 最小值 (用於數值類型)
    """
    while True:
        value = input(prompt)
        if not value:  # 輸入不能是空白
            if default is not None:
                return default
            continue
        try:
            result = input_type(value)
            if min_value is not None and result < min_value:
                print(f"{Fore.YELLOW}Value must be at least {min_value}{Style.RESET_ALL}")
                continue
            return result
        except ValueError:
            print(f"{Fore.YELLOW}Please enter a valid {input_type.__name__}{Style.RESET_ALL}")

def test_connection(host, user, password):
    """測試 ESXi 連線
    
    Returns:
        tuple: (bool, ServiceInstance) - 連線成功返回 (True, si)，失敗返回 (False, None)
    """
    try:
        context = ssl._create_unverified_context()
        si = SmartConnect(host=host, user=user, pwd=password, sslContext=context)
        if si:
            print(f"{Fore.GREEN}Successfully connected to ESXi host{Style.RESET_ALL}")
            return True, si
        return False, None
    except Exception as e:
        print(f"{Fore.RED}Failed to connect to ESXi host: {e}{Style.RESET_ALL}")
        return False, None

def list_vms(si):
    """列出ESXi主機上的所有VM, 按創建時間排序
    
    Args:
        si: 服務實例
    Returns:
        list: VM名稱列表
    """
    try:
        content = si.RetrieveContent()
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        
        # 獲取VM並記錄創建時間
        vms_with_time = []
        for vm in container.view:
            # 使用VM的創建時間，如果沒有則使用最後修改時間
            create_time = vm.config.createDate or vm.config.modified
            vms_with_time.append((vm.name, create_time))
        
        container.Destroy()
        
        if not vms_with_time:
            print(f"{Fore.YELLOW}No VMs found on this host{Style.RESET_ALL}")
            return []
        
        # 按時間排序，最新的在最後
        vms_with_time.sort(key=lambda x: x[1])
        vm_names = [vm[0] for vm in vms_with_time]
            
        print(f"\nAvailable VMs (oldest to newest):")
        for i, name in enumerate(vm_names, 1):
            print(f"{i}) {name}")
        return vm_names
    except Exception as e:
        print(f"{Fore.RED}Error listing VMs: {e}{Style.RESET_ALL}")
        return []



def print_menu():
    print("\n=== Add PCI Passthrough VM Options ===")


def main():
    # 預設配置
    host = "10.241.180.69"         # ESXi 主機 IP
    user = "root"                  # ESXi 使用者
    password = "Admin!23"          # ESXi 密碼
    vm_name = "TestVM"             # 新 VM 名稱
    si = None

    try:
        print_menu() 
        while True:
            host = get_valid_input("Enter Host IP: ")
            if host:
                # 測試連線
                connected, si = test_connection(host, user, password)
                if not connected:
                    continue
                break
        
        # 列出可用的VM
        vm_list = list_vms(si)
        if vm_list:
            while True:
                vm_input = input("\nEnter VM number or name (or 'q' to quit): ")
                if vm_input.lower() == 'q':
                    break
                
                try:
                    # 嘗試將輸入轉換為數字
                    idx = int(vm_input) - 1
                    if 0 <= idx < len(vm_list):
                        vm_name = vm_list[idx]
                        break
                except ValueError:
                    # 如果輸入不是數字,直接使用輸入的名稱
                    if vm_input in vm_list:
                        vm_name = vm_input
                        break
                
                print(f"{Fore.YELLOW}Invalid selection. Please try again.{Style.RESET_ALL}")
            
            if vm_name:
                add_vm_options(si, vm_name)
                

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")
    finally:
        # 確保連接被正確關閉
        if si:
            Disconnect(si)

if __name__ == "__main__":
    main()