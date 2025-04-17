from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl
import os
from colorama import init, Fore, Style
import requests

# Initialize colorama
init()

def create_vm(host, user, password, vm_name, datastore_name, memory_mb, num_cpu, disk_gb, force_overwrite):
    # 連接到 ESXi 主機
    context = ssl._create_unverified_context()
    si = SmartConnect(host=host, user=user, pwd=password, sslContext=context)
    
    try:
        content = si.RetrieveContent()
        
        # 檢查是否已存在同名 VM
        vm_folder = content.rootFolder.childEntity[0].vmFolder
        vm_list = vm_folder.childEntity
        existing_vm = None
        
        for vm in vm_list:
            if vm.name == vm_name:
                existing_vm = vm
                break
        
        if existing_vm:
            if force_overwrite:
                print(f"{Fore.YELLOW}VM '{vm_name}' already exists.")
                task = existing_vm.Destroy_Task()
                while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                    pass
                if task.info.state != vim.TaskInfo.State.success:
                    print(f"{Fore.RED}Failed to delete existing VM: {task.info.error}{Style.RESET_ALL}")
                    return None
            else:
                print(f"{Fore.YELLOW}VM '{vm_name}' already exists. Use a different name.{Style.RESET_ALL}")
                return None
        
        # 獲取 datacenter
        datacenter = content.rootFolder.childEntity[0]
        
        # 獲取 datastore
        datastore = None
        for ds in content.rootFolder.childEntity[0].datastore:
            if ds.name == datastore_name:
                datastore = ds
                break
        
        if not datastore:
            raise Exception(f"{Fore.YELLOW}Datastore '{datastore_name}' not found{Style.RESET_ALL}")
        
        # 獲取 resource pool
        resource_pool = content.rootFolder.childEntity[0].hostFolder.childEntity[0].resourcePool
        
        # 獲取 VM 文件夾
        vm_folder = datacenter.vmFolder
        
        # 創建 VM 配置
        vm_config = vim.vm.ConfigSpec()
        vm_config.name = vm_name
        vm_config.memoryMB = memory_mb
        vm_config.numCPUs = num_cpu
        vm_config.guestId = 'otherGuest64'
        
        # 設置 VM 文件位置
        vm_config.files = vim.vm.FileInfo()
        vm_config.files.vmPathName = f"[{datastore_name}] {vm_name}/{vm_name}.vmx"
        
        # 創建硬碟配置
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.fileOperation = "create"
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        
        # 創建硬碟
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        disk_spec.device.backing.diskMode = 'persistent'
        disk_spec.device.backing.fileName = f"[{datastore_name}] {vm_name}/{vm_name}.vmdk"
        disk_spec.device.backing.thinProvisioned = True
        
        # 設置硬碟大小
        disk_spec.device.capacityInKB = disk_gb * 1024 * 1024
        
        # 添加 SCSI 控制器
        scsi_controller = vim.vm.device.VirtualLsiLogicController()
        scsi_controller.key = 1000
        scsi_controller.busNumber = 0
        scsi_controller.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.noSharing
        
        scsi_controller_spec = vim.vm.device.VirtualDeviceSpec()
        scsi_controller_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        scsi_controller_spec.device = scsi_controller
        
        disk_spec.device.controllerKey = scsi_controller.key
        disk_spec.device.unitNumber = 0
        
        # 添加 CD/DVD 光碟機
        cdrom_spec = vim.vm.device.VirtualDeviceSpec()
        cdrom_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        cdrom_spec.device = vim.vm.device.VirtualCdrom()
        cdrom_spec.device.key = 3000
        cdrom_spec.device.controllerKey = 201  # IDE controller key
        cdrom_spec.device.unitNumber = 0
        
        # 設置為主機裝置
        cdrom_spec.device.backing = vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo()
        cdrom_spec.device.backing.exclusive = False
        
        # 設置開機時連接
        cdrom_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        cdrom_spec.device.connectable.startConnected = True
        cdrom_spec.device.connectable.allowGuestControl = True
        cdrom_spec.device.connectable.connected = True
        
        # 添加 IDE 控制器
        ide_controller = vim.vm.device.VirtualIDEController()
        ide_controller.key = 201
        ide_controller.busNumber = 0
        
        ide_controller_spec = vim.vm.device.VirtualDeviceSpec()
        ide_controller_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        ide_controller_spec.device = ide_controller
        
        # 更新設備配置列表
        vm_config.deviceChange = [scsi_controller_spec, disk_spec, ide_controller_spec, cdrom_spec]
        
        # 創建 VM
        task = vm_folder.CreateVM_Task(config=vm_config, pool=resource_pool)
        print(f"\nTask to create VM '{vm_name}' started")
        
        # 等待任務完成
        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
            pass
        
        if task.info.state == vim.TaskInfo.State.success:
            print(f"{Fore.GREEN}VM '{vm_name}' created successfully{Style.RESET_ALL}")
            return si  # 返回連接實例
        else:
            print(f"{Fore.RED}Failed to create VM: {task.info.error}{Style.RESET_ALL}")
            return None
            
    except Exception as e:
        print(f"{Fore.RED}Error creating VM: {e}{Style.RESET_ALL}")
        Disconnect(si)
        return None

# TODO 從 OVF 和 VMDK 檔案部署虛擬機(目前上傳會失敗先停用)
def deploy_ovf_vm(host, user, password, ovf_folder_path, vm_name, datastore_name, force_overwrite):
    """
    從 OVF 和 VMDK 檔案部署虛擬機
    """
    # 連接到 ESXi 主機
    context = ssl._create_unverified_context()
    si = SmartConnect(host=host, user=user, pwd=password, sslContext=context)
    
    try:
        content = si.RetrieveContent()
        
        # 檢查是否已存在同名 VM
        vm_folder = content.rootFolder.childEntity[0].vmFolder
        vm_list = vm_folder.childEntity
        existing_vm = None
        
        for vm in vm_list:
            if vm.name == vm_name:
                existing_vm = vm
                break
        
        if existing_vm:
            if force_overwrite:
                print(f"{Fore.YELLOW}VM '{vm_name}' already exists.{Style.RESET_ALL}")
                task = existing_vm.Destroy_Task()
                while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                    pass
                if task.info.state != vim.TaskInfo.State.success:
                    print(f"{Fore.RED}Failed to delete existing VM: {task.info.error}{Style.RESET_ALL}")
                    return None
            else:
                print(f"{Fore.YELLOW}VM '{vm_name}' already exists.{Style.RESET_ALL}")
                return None
        
        # 找到 OVF 檔案
        ovf_file = None
        vmdk_files = []
        for file in os.listdir(ovf_folder_path):
            if file.endswith('.ovf'):
                ovf_file = os.path.join(ovf_folder_path, file)
            elif file.endswith('.vmdk'):
                vmdk_files.append(os.path.join(ovf_folder_path, file))
        
        if not ovf_file:
            raise Exception("No .ovf file found in the specified folder")
        if not vmdk_files:
            raise Exception("No .vmdk files found in the specified folder")
        
        # 讀取 OVF 檔案
        with open(ovf_file, 'r', encoding='utf-8') as f:
            ovf_content = f.read()
        
        # 獲取必要的物件參考
        resource_pool = content.rootFolder.childEntity[0].hostFolder.childEntity[0].resourcePool
        datastore = None
        for ds in content.rootFolder.childEntity[0].datastore:
            if ds.name == datastore_name:
                datastore = ds
                break
        
        if not datastore:
            raise Exception(f"Datastore '{datastore_name}' not found")
        
        # 創建 ImportSpec
        cisp = vim.OvfManager.CreateImportSpecParams()
        cisp.entityName = vm_name
        cisp.diskProvisioning = "thin"
        
        ovf_manager = content.ovfManager
        import_spec = ovf_manager.CreateImportSpec(
            ovf_content,
            resource_pool,
            datastore,
            cisp
        )
        
        if import_spec.error:
            raise Exception(f"Failed to create import spec: {import_spec.error}")
        
        # 開始導入任務
        lease = resource_pool.ImportVApp(import_spec.importSpec, vm_folder)
        
        # 等待租約準備就緒
        while lease.state == vim.HttpNfcLease.State.initializing:
            pass
        
        if lease.state == vim.HttpNfcLease.State.error:
            raise Exception(f"Lease error: {lease.error}")
        
        print(f"\nStarting deployment of VM '{vm_name}' from OVF template")
        
        # 獲取上傳 URL
        upload_urls = {}
        for device_url in lease.info.deviceUrl:
            upload_urls[device_url.importKey] = device_url.url.replace('*', host)
        
        # 上傳所有 VMDK 文件
        total_bytes = 0
        for vmdk_file in vmdk_files:
            total_bytes += os.path.getsize(vmdk_file)
        
        bytes_uploaded = 0
        for device_import_key, device_url in upload_urls.items():
            vmdk_file = vmdk_files[0]  # 假設只有一個 VMDK 文件
            
            print(f"\nUploading {os.path.basename(vmdk_file)}...")
            
            # 禁用 SSL 驗證警告
            requests.packages.urllib3.disable_warnings()
            
            # 讀取並上傳文件
            with open(vmdk_file, 'rb') as f:
                headers = {'Content-Type': 'application/x-vnd.vmware-streamVmdk'}
                response = requests.put(device_url, data=f, headers=headers, verify=False)
                
                if response.status_code != 200:
                    lease.Abort()
                    raise Exception(f"Upload failed: {response.status_code}")
                
                bytes_uploaded += os.path.getsize(vmdk_file)
                
                # 更新進度
                percent = int((bytes_uploaded / total_bytes) * 100)
                lease.Progress(percent)
                print(f"Upload progress: {percent}%")
        
        # 完成部署
        print("\nFinalizing deployment...")
        lease.Complete()
        print(f"{Fore.GREEN}VM '{vm_name}' deployed successfully from OVF template{Style.RESET_ALL}")
        return si
        
    except Exception as e:
        print(f"{Fore.RED}Error deploying VM from OVF: {e}{Style.RESET_ALL}")
        if 'lease' in locals():
            lease.Abort()
        Disconnect(si)
        return None

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

def delete_vm(si, vm_name):
    """
    刪除指定的虛擬機
    
    參數：
    si - 服務實例
    vm_name - 虛擬機名稱
    """
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
            print(f"{Fore.RED}VM '{vm_name}' not found{Style.RESET_ALL}")
            return
        
        # 檢查VM電源狀態
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
            print(f"{Fore.YELLOW}VM '{vm_name}' is currently powered on{Style.RESET_ALL}")
            while True:
                power_off = input("Would you like to power off the VM before deletion? (y/n): ").upper()
                if power_off == 'Y':
                    print(f"Powering off VM '{vm_name}'...")
                    task = vm.PowerOffVM_Task()
                    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                        pass
                    if task.info.state != vim.TaskInfo.State.success:
                        print(f"{Fore.RED}Failed to power off VM: {task.info.error}{Style.RESET_ALL}")
                        return
                    print(f"{Fore.GREEN}VM powered off successfully{Style.RESET_ALL}")
                    break
                elif power_off == 'N':
                    print(f"{Fore.YELLOW}Cannot delete a powered on VM. Operation cancelled.{Style.RESET_ALL}")
                    return
                else:
                    print(f"{Fore.YELLOW}Please enter Y or N{Style.RESET_ALL}")
                    continue
        
        # 確認刪除
        while True:
            confirm = input(f"Are you sure you want to delete VM {Fore.CYAN}'{vm_name}'{Style.RESET_ALL}? (y/n): ").upper()
            if confirm == 'Y':
                break
            elif confirm == 'N':
                print(f"{Fore.YELLOW}Delete operation cancelled{Style.RESET_ALL}")
                return
            else:
                print(f"{Fore.YELLOW}Please enter Y or N{Style.RESET_ALL}")
                continue
            
        # 執行刪除任務
        task = vm.Destroy_Task()
        print(f"\nDeleting VM '{vm_name}'...")
        
        # 等待任務完成
        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
            pass
        
        if task.info.state == vim.TaskInfo.State.success:
            print(f"{Fore.GREEN}VM '{vm_name}' deleted successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to delete VM: {task.info.error}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}Error deleting VM: {e}{Style.RESET_ALL}")

def print_menu():
    print("\n=== ESXi VM Management Tool ===")
    print("1) Create New VM")
    print("2) Add PCI Passthrough VM Options")
    print("3) Delete VM")
    # print("4) Deploy OVF VM")
    print("Q) Quit")

def main():
    # 預設配置
    host = "10.241.180.69"         # ESXi 主機 IP
    user = "root"                  # ESXi 使用者
    password = "Admin!23"          # ESXi 密碼
    vm_name = "TestVM"             # 新 VM 名稱
    datastore_name = "datastore1"  # 資料存儲名稱
    memory_mb = 1024               # 記憶體大小
    num_cpu = 1                    # 處理器數量
    disk_gb = 40                   # 硬碟大小
    force_overwrite = False        # 是否強制覆蓋
    ovf_folder_path = "./OVF"      # OVF 檔案資料夾路徑
    si = None

    try:
        print_menu()  # 只在開始時顯示一次選單
        while True:
            choice = input("Please select an option: ")
            
            if choice.lower() == "q":
                break
                
            elif choice == "1":
                while True:
                    host = get_valid_input("Enter Host IP: ")
                    if host:
                        # 測試連線
                        connected, si = test_connection(host, user, password)
                        if not connected:
                            continue
                        break
                
                while True:
                    vm_name = get_valid_input("Enter VM name: ")
                    if vm_name:
                        break
                
                memory_mb = get_valid_input("Enter memory size (MB): ", int, min_value=1)
                num_cpu = get_valid_input("Enter number of CPUs: ", int, min_value=1)
                disk_gb = get_valid_input("Enter disk size (GB): ", int, min_value=1)
                
                # 使用已建立的連線來創建 VM
                si = create_vm(host, user, password, vm_name, datastore_name, 
                             memory_mb, num_cpu, disk_gb, force_overwrite)
                
            elif choice == "2":
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
                
            elif choice == "3":
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
                        delete_vm(si, vm_name)
            
            # elif choice == "4":
            #     while True:
            #         host = get_valid_input("Enter Host IP: ")
            #         if host:
            #             # 測試連線
            #             connected, si = test_connection(host, user, password)
            #             if not connected:
            #                 continue
            #             break
                
            #     while True:
            #         vm_name = get_valid_input("Enter VM name: ")
            #         if vm_name:
            #             break
                    
            #     ovf_folder_path = get_valid_input("Enter OVF folder path (default: ./OVF): ", default="./OVF")
                
            #     si = deploy_ovf_vm(host, user, password, ovf_folder_path, 
            #                      vm_name, datastore_name, force_overwrite)

            else:
                continue
            
            # 每次操作完成後重新顯示選單
            print_menu()

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