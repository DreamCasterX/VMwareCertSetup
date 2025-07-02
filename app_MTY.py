import streamlit as st
from main_MTY import SUTConfigurator, VIVaConfigurator, AgentConfigurator, VCConfigurator, OVFManager, DNSConfigurator, PciPassthruConfigurator, ResultLogCopier
import pandas as pd
import os
import json
import subprocess
import time
import re
from pyVmomi import vim
import concurrent.futures

# Monkey patch: add get_available_networks to OVFManager
def _ovf_get_available_networks(self, si):
    try:
        content = si.RetrieveContent()
        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.Network], True)
        networks = []
        for network in container.view:
            if hasattr(network, 'name'):
                networks.append(network.name)
        container.Destroy()
        return sorted(networks)
    except Exception as e:
        print(f"Error getting available networks: {e}")
        return []

OVFManager.get_available_networks = _ovf_get_available_networks

# 用於重置 Agent Config 流程的 helper
RESET_AGENT_KEYS = ['agent_step','agent_form_data','agent_ssh','agent_success_msgs','agent_uploaded','agent_external_dns','agent_url','agent_overwrite_confirm','agent_pending_file']
def agent_reset_button():
    if st.button("Reset/Restart"):
        for k in RESET_AGENT_KEYS:
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()

# 用於重置 vCenter Deploy 流程的 helper
VC_RESET_KEYS = ['vc_step', 'vc_form_data', 'vc_temp_iso_path', 'vc_si', 'vc_deployment_network', 'vc_success_msgs']
def vc_reset_button():
    if st.button("Reset/Restart"):
        for k in VC_RESET_KEYS:
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()

def get_sysinfo(ssh):
    info = {}
    commands = {
        'Product Name': "esxcli hardware platform get | grep 'Product Name' | awk -F ': ' '{print $2}'",
        'OS version': "vmware -v",
        'BMC IP': "esxcli hardware ipmi bmc get | grep 'IPv4Address' | awk -F ': ' '{print $2}'",
        'Hyper-Threading': "esxcli hardware cpu global get | grep 'Hyperthreading Enabled' | awk -F ': ' '{print $2}' | sed 's/true/Enabled/;s/false/Disabled/'",
        'Secure Boot': "python3 /usr/lib/vmware/secureboot/bin/secureBoot.py -s",
         'Secure boot enforcement': "esxcli system settings encryption get  | grep 'Require Secure Boot' | awk -F ': ' '{print $2}' | sed 's/true/Enabled/;s/false/Disabled/'",
        'TPM': "esxcli hardware trustedboot get | grep -i TPM | awk -F ': ' '{print $2}' | sed 's/true/Enabled/;s/false/Disabled/'",
        'Firewall': "esxcli network firewall get | grep 'Enabled' | awk -F ': ' '{print $2}' | sed 's/true/On/;s/false/Off/'",
        'OS IP': "esxcli network ip interface ipv4 get | awk 'NR==3 {print $2}'",
        'Submask': "esxcli network ip interface ipv4 get | awk 'NR==3 {print $3}'",
        'Gateway': "esxcli network ip interface ipv4 get | awk 'NR==3 {print $6}'",
        'DNS server': "esxcli network ip dns server list | awk -F ': ' '{print $2}'",
        'DNS hostname': "esxcli system hostname get | grep 'Fully Qualified Domain Name' | awk -F ': ' '{print $2}'",
    }
    for label, cmd in commands.items():
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            result = stdout.read().decode().strip()
            info[label] = result
        except Exception as e:
            info[label] = f"Error: {e}"
    return info

st.set_page_config(page_title="VMware Cert Setup Tool", layout="centered")

st.markdown(
    '''
    <style>
    .block-container {padding-top: 1.5rem; padding-bottom: 1.5rem;}
    section[data-testid="stSidebar"] {min-width: 180px;}
    div[data-testid="column"] {padding-left: 0.5rem; padding-right: 0.5rem;}
    </style>
    ''',
    unsafe_allow_html=True
)

st.markdown("""
    <style>
    .stAlert {
        margin-top: 0.2rem;
        margin-bottom: 0.2rem;
        padding-top: 0.2rem;
        padding-bottom: 0.2rem;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🖥️ VMware Cert Test Environment Setup Tool")
st.markdown("""

*Select a function from the list*
""")

menu = [
    "Config SUT",
    "Config VIVa",
    "Config Agent",
    "Deploy vCenter",
    "Deploy/Export OVF",
    "Manage DNS host record",
    "Enable PCI passthrough for NVIDIA GPU",
    "Copy Agent execution log"
]

col_menu, col_content = st.columns([0.22, 0.78], gap="small")

with col_menu:
    choice = st.radio("", menu, label_visibility="collapsed")

with col_content:
    if choice == "Config SUT":
        st.header(":blue[Config SUT]")
        st.info("""
        **Prerequisites**
        - SUT installed VMware ESXi OS
        - SUT enabled :orange[SSH access]
        - SUT obtained the local DHCP IP address (192.168.x.x)
        """, icon="ℹ️")
        

        # 初始化 session state
        if 'sut_step' not in st.session_state:
            st.session_state['sut_step'] = 0
        if 'sut_form_data' not in st.session_state:
            st.session_state['sut_form_data'] = {}
        if 'sut_ssh' not in st.session_state:
            st.session_state['sut_ssh'] = None
        if 'sut_sysinfo' not in st.session_state:
            st.session_state['sut_sysinfo'] = None
        if 'sut_hostname' not in st.session_state:
            st.session_state['sut_hostname'] = None
        if 'sut_continue_clicked' not in st.session_state:
            st.session_state['sut_continue_clicked'] = False

        if st.session_state['sut_step'] == 0:
            form_col, _ = st.columns([2, 1])
            with form_col:
                with st.form("sut_form"):
                    sut_ip = st.text_input("Enter SUT IP address")
                    root_password = st.text_input("Enter root password", value="Passw0rd!", type="password")
                    static_ip = st.text_input("New static IP address")
                    subnet = st.text_input("Subnet Mask", value="255.255.255.0")
                    gateway = st.text_input("Default Gateway", value="192.168.10.10")
                    dns = st.text_input("Primary DNS", value="192.168.10.10")
                    hostname = st.text_input("DNS Hostname（auto fill-in if left empty）")
                    submitted = st.form_submit_button("Start Configuration", type="primary")
            
            if submitted:
                with st.spinner("Enabling ESXi Shell..."):
                    configurator = SUTConfigurator()
                    configurator.password = root_password
                    # 驗證 DHCP IP
                    if not configurator.validate_ip(sut_ip):
                        st.error("❌ Invalid DHCP IP format")
                        st.stop()
                    if not configurator.ping_check(sut_ip):
                        st.error("❌ Unable to ping SUT IP. Please check the network and IP address.")
                        st.stop()
                    ssh = configurator.ssh_connect(sut_ip, configurator.username, configurator.password)
                    if not ssh:
                        st.error("❌ SSH connection failed. Please check IP/password/SSH status.")
                        st.stop()
                    if not configurator.enable_shell(ssh):
                        st.error("❌ Failed to enable ESXi Shell.")
                        st.stop()
                    st.session_state['sut_form_data'] = {
                        'sut_ip': sut_ip,
                        'root_password': root_password,
                        'static_ip': static_ip,
                        'subnet': subnet,
                        'gateway': gateway,
                        'dns': dns,
                        'hostname': hostname
                    }
                    st.session_state['sut_ssh'] = ssh
                    st.session_state['sut_step'] = 1
                    st.rerun()

        # 步驟 1: 顯示系統資訊，並詢問是否繼續
        elif st.session_state['sut_step'] == 1:
            ssh = st.session_state['sut_ssh']
            st.info("🔍 Getting the current system information...")
            if st.session_state['sut_sysinfo'] is None:
                st.session_state['sut_sysinfo'] = get_sysinfo(ssh)
            st.subheader("Current system information")
            df = pd.DataFrame(st.session_state['sut_sysinfo'].items(), columns=['Attribute', 'Value'])
            table_html = df.to_html(header=False, index=False, border=0, escape=False)
            st.markdown(table_html, unsafe_allow_html=True)
            
            
            #st.dataframe(df, use_container_width=True)
            st.button(
                "Continue",
                on_click=lambda: st.session_state.update(sut_step=2, sut_continue_clicked=True),
                disabled=st.session_state.sut_continue_clicked,
                type="primary"
            )

        # 步驟 2: 設定靜態 IP
        elif st.session_state['sut_step'] == 2:
            with st.spinner("⚙️ Setting static IP..."):
                data = st.session_state['sut_form_data']
                configurator = SUTConfigurator()
                configurator.password = data['root_password']
                ssh = st.session_state['sut_ssh']
                static_ip = data['static_ip']
                subnet = data['subnet']
                gateway = data['gateway']

                if not configurator.validate_ip(static_ip) or configurator.ping_check(static_ip):
                    st.error("❌ Invalid static IP format, or IP is already in use.")
                    st.stop()
                if not configurator.validate_ip(subnet) or not configurator.validate_ip(gateway):
                    st.error("❌ Invalid subnet mask or gateway format.")
                    st.stop()
                if not configurator.configure_network(ssh, static_ip, subnet, gateway):
                    st.error("❌ Failed to configure static IP.")
                    st.stop()

                ssh.close()
                st.info("🔄 Configuring network settings......")
                import time; time.sleep(5)

                ssh = configurator.ssh_connect(static_ip, configurator.username, configurator.password)
                if not ssh:
                    st.error("❌ Unable to reconnect with the new IP address.")
                    st.stop()

                st.session_state['sut_ssh'] = ssh
            st.session_state['sut_step'] = 3
            st.rerun()

        # 步驟 3: 設定 DNS
        elif st.session_state['sut_step'] == 3:
            with st.spinner("⚙️ Configuring DNS settings..."):
                data = st.session_state['sut_form_data']
                configurator = SUTConfigurator()
                configurator.password = data['root_password']
                ssh = st.session_state['sut_ssh']
                dns = data['dns']
                hostname = data['hostname']
                static_ip = data['static_ip']

                if not configurator.validate_ip(dns):
                    st.error("❌ Invalid DNS IP format")
                    st.stop()
                if hostname.strip() == "":
                    last_octet = static_ip.split(".")[-1]
                    hostname = f"esxi{last_octet}"
                st.session_state['sut_hostname'] = hostname

                if not configurator.configure_dns(ssh, dns, hostname):
                    st.error("❌ Failed to configure DNS")
                    st.stop()
            st.session_state['sut_step'] = 4
            st.rerun()

        # 步驟 4: 關閉防火牆
        elif st.session_state['sut_step'] == 4:
            with st.spinner("🔒 Turning off the firewall..."):
                configurator = SUTConfigurator()
                ssh = st.session_state['sut_ssh']
                if not configurator.configure_firewall(ssh):
                    st.error("❌ Failed to turn off the firewall")
                    st.stop()
            st.session_state['sut_step'] = 5
            st.rerun()

        # 步驟 5: 重新取得系統資訊，結束
        elif st.session_state['sut_step'] == 5:
            ssh = st.session_state.get('sut_ssh')

            # 僅在 SSH 連線仍然活動時（即首次到達此步驟），才執行更新。
            if ssh and ssh.get_transport() and ssh.get_transport().is_active():
                with st.spinner("📋 Fetching the final system information..."):
                    st.session_state['sut_sysinfo'] = get_sysinfo(ssh)
                    ssh.close() # 完成後立即關閉連線
                                
            st.subheader("Updated system information")
            
            # 確保 session 中有資訊可供顯示
            if st.session_state.get('sut_sysinfo'):
                df = pd.DataFrame(st.session_state['sut_sysinfo'].items(), columns=['Attribute', 'Value'])
                table_html = df.to_html(header=False, index=False, border=0, escape=False)
                st.markdown(table_html, unsafe_allow_html=True)
                st.success("🎉 All configurations have been completed！Remember to add the DNS host record：")
                hostname = st.session_state.get('sut_hostname', 'N/A')
                static_ip = st.session_state.get('sut_form_data', {}).get('static_ip', 'N/A')
                st.markdown(f"**Hostname：** `{hostname}`")
                st.markdown(f"**IP：** `{static_ip}`")
            else:
                st.error("An error occurred or the information has expired. Please reconfigure.")

            # Reset流程
            if st.button("Reset/Restart"):
                for k in ['sut_step','sut_form_data','sut_ssh','sut_sysinfo','sut_hostname', 'sut_continue_clicked']:
                    if k in st.session_state:
                        del st.session_state[k]
                st.rerun()
    elif choice == "Config VIVa":
        st.header(":blue[Config VIVa]")
        if 'viva_step' not in st.session_state:
            st.session_state['viva_step'] = 0
        if 'viva_form_data' not in st.session_state:
            st.session_state['viva_form_data'] = {}
        if 'viva_ssh' not in st.session_state:
            st.session_state['viva_ssh'] = None
        if 'viva_result' not in st.session_state:
            st.session_state['viva_result'] = ""
        if 'viva_continue_clicked' not in st.session_state:
            st.session_state['viva_continue_clicked'] = False
        if 'viva_success_msgs' not in st.session_state:
            st.session_state['viva_success_msgs'] = []

        # 顯示所有已完成步驟的成功訊息
        for msg in st.session_state['viva_success_msgs']:
            st.success(msg)

        if st.session_state['viva_step'] == 0:
            st.info("""
            **Prerequisites**
            - Downloaded the 'viva-xxxx.ova' from Broadcom TAP website
            - Deployed the 'viva-xxxx.ova' on TC
            - Obtained the DHCP IP address of VIVa from TC
            """, icon="ℹ️")
            form_col, _ = st.columns([2, 1])
            with form_col:
                with st.form("viva_form"):
                    viva_ip = st.text_input("Enter VIVa local IP address (192.168.x.x)")
                    submitted = st.form_submit_button("Start Configuration", type="primary")
            if submitted:
                configurator = VIVaConfigurator()
                if not configurator.validate_ip(viva_ip):
                    st.error("❌ Invalid IP format")
                    st.stop()
                ssh = configurator.ssh_connect(viva_ip, configurator.username, configurator.password)
                if not ssh:
                    st.error("❌ SSH connection failed. Please check IP/password/SSH status.")
                    st.stop()
                st.session_state['viva_form_data'] = {'viva_ip': viva_ip}
                st.session_state['viva_ssh'] = ssh
                st.session_state['viva_success_msgs'] = []  # reset messages on restart
                st.session_state['viva_step'] = 1
                st.rerun()

        elif st.session_state['viva_step'] == 1:
            st.info("Setting hostname to photon-viva...")
            configurator = VIVaConfigurator()
            ssh = st.session_state['viva_ssh']
            if not configurator.set_hostname(ssh):
                ssh.close()
                st.error("❌ Failed to set hostname.")
                st.stop()
            st.session_state['viva_success_msgs'].append("Hostname configuration successful.")
            st.session_state['viva_step'] = 2
            st.rerun()

        elif st.session_state['viva_step'] == 2:
            st.info("Disabling password expiration...")
            configurator = VIVaConfigurator()
            ssh = st.session_state['viva_ssh']
            try:
                stdin, stdout, stderr = ssh.exec_command('chage -M 99999 root')
                if stdout.channel.recv_exit_status() != 0:
                    st.error("❌ Failed to disable password expiration.")
                    st.stop()
            except Exception as e:
                st.error(f"❌ Error disabling password expiration: {e}")
                st.stop()
            st.session_state['viva_success_msgs'].append("Password expiration disabled.")
            st.session_state['viva_step'] = 3
            st.rerun()

        elif st.session_state['viva_step'] == 3:
            st.info("Configuring /etc/hosts...")
            configurator = VIVaConfigurator()
            ssh = st.session_state['viva_ssh']
            if not configurator.configure_hosts_file(ssh, st.session_state['viva_form_data']['viva_ip']):
                ssh.close()
                st.error("❌ Failed to configure hosts file.")
                st.stop()
            st.session_state['viva_success_msgs'].append("Hosts file configuration successful.")
            st.session_state['viva_step'] = 4
            st.rerun()

        elif st.session_state['viva_step'] == 4:
            st.info("Checking Internet connectivity...")
            configurator = VIVaConfigurator()
            ssh = st.session_state['viva_ssh']
            def check_internet_with_timeout(ssh, timeout=15):
                def inner():
                    return configurator.check_internet(ssh)
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(inner)
                    try:
                        return future.result(timeout=timeout)
                    except concurrent.futures.TimeoutError:
                        return "timeout"
            result = check_internet_with_timeout(ssh, timeout=15)
            if result == "timeout":
                st.error("❌ Internet connectivity check timed out. Please check your network and try again.")
                if st.button("Reset/Restart"):
                    for k in ['viva_step','viva_form_data','viva_ssh','viva_result','viva_continue_clicked','viva_success_msgs']:
                        if k in st.session_state:
                            del st.session_state[k]
                    st.rerun()
                st.stop()
            elif not result:
                st.error("❌ Internet connectivity check failed.")
                if st.button("Reset/Restart"):
                    for k in ['viva_step','viva_form_data','viva_ssh','viva_result','viva_continue_clicked','viva_success_msgs']:
                        if k in st.session_state:
                            del st.session_state[k]
                    st.rerun()
                st.stop()
            st.session_state['viva_success_msgs'].append("Internet connectivity check successful.")
            st.session_state['viva_step'] = 5
            st.rerun()

        elif st.session_state['viva_step'] == 5:
            with st.spinner("🔄 Refreshing VIVa service..."):
                configurator = VIVaConfigurator()
                ssh = st.session_state['viva_ssh']
                try:
                    stdin, stdout, stderr = ssh.exec_command("bash /opt/broadcom/viva/refresh_viva_service.sh")
                    if stdout.channel.recv_exit_status() != 0:
                        st.error("❌ Failed to refresh VIVa service.")
                        st.stop()
                    success, new_ssh = configurator.configure_internal_network_config(ssh, st.session_state['viva_form_data']['viva_ip'])
                    if not success or not new_ssh:
                        st.error("❌ Internal network configuration failed.")
                        st.stop()
                    new_ssh.close()
                    st.session_state['viva_ssh'] = None  # avoid using closed ssh later
                except Exception as e:
                    st.error(f"❌ Error: {e}")
                    st.stop()
                st.session_state['viva_success_msgs'].append("VIVa service refresh successful.")
                st.session_state['viva_success_msgs'].append("🎉 All configurations have been completed！")
                st.session_state['viva_step'] = 6
                st.rerun()

        elif st.session_state['viva_step'] == 6:
            # 顯示所有 success 訊息和下載提示
            url = "http://cert-viva-local/Certs"
            st.markdown(f"**Please ensure the jump server has Internet connectivity, then open your browser and visit: [cert-viva-local/Certs]({url})**")
            st.markdown("On the web UI, download the :orange[Agent image (.ova)] and :orange[Runlist (.json)] after filling in all the required data.")
            if st.button("Reset/Restart"):
                for k in ['viva_step','viva_form_data','viva_ssh','viva_result','viva_continue_clicked','viva_success_msgs']:
                    if k in st.session_state:
                        del st.session_state[k]
                st.rerun()
    elif choice == "Config Agent":
        st.header(":blue[Config Agent]")
        if 'agent_step' not in st.session_state:
            st.session_state['agent_step'] = 0
        if 'agent_form_data' not in st.session_state:
            st.session_state['agent_form_data'] = {}
        if 'agent_ssh' not in st.session_state:
            st.session_state['agent_ssh'] = None
        if 'agent_success_msgs' not in st.session_state:
            st.session_state['agent_success_msgs'] = []
        if 'agent_uploaded' not in st.session_state:
            st.session_state['agent_uploaded'] = False
        if 'agent_external_dns' not in st.session_state:
            st.session_state['agent_external_dns'] = None
        if 'agent_url' not in st.session_state:
            st.session_state['agent_url'] = None

        if st.session_state['agent_step'] == 0:
            st.info("""
            **Prerequisites**
            - Downloaded the Agent image (.ova) and Runlist (.json) from VIVa
            - Deployed the agent image on TC
            - Obtained the DHCP IP address of Agent from TC
            """, icon="ℹ️")
            st.session_state['agent_success_msgs'] = []
            form_col, _ = st.columns([2, 1])
            with form_col:
                with st.form("agent_form"):
                    agent_ip = st.text_input("Enter Agent local IP address (192.168.x.x)")
                    submitted = st.form_submit_button("Start Configuration", type="primary")
            if submitted:
                configurator = AgentConfigurator()
                if not configurator.validate_ip(agent_ip):
                    st.error("❌ Invalid IP format")
                    st.stop()
                ssh = configurator.ssh_connect(agent_ip, configurator.username, configurator.password)
                if not ssh:
                    st.error("❌ SSH connection failed. Please check IP/password/SSH status.")
                    st.stop()
                st.session_state['agent_form_data'] = {'agent_ip': agent_ip}
                st.session_state['agent_ssh'] = ssh
                st.session_state['agent_success_msgs'] = [] # 重置/初始化訊息列表
                st.session_state['agent_uploaded'] = False
                st.session_state['agent_step'] = 1
                st.rerun()

        elif st.session_state['agent_step'] == 1:
            st.info("Transferring runlist to Agent...")
            form_col, _ = st.columns([2, 1])
            with form_col:
                if not st.session_state['agent_uploaded']:
                    uploaded_file = st.file_uploader("Upload runlist.json", type=["json"])
                    # 覆蓋確認後直接進行覆蓋，不再依賴 file_uploader
                    if st.session_state.get('agent_overwrite_confirm', False) and 'agent_pending_file' in st.session_state:
                        try:
                            ssh = st.session_state['agent_ssh']
                            sftp = ssh.open_sftp()
                            file_bytes = st.session_state['agent_pending_file']
                            with sftp.file('/vmware/input/runlist.json', 'wb') as f:
                                f.write(file_bytes)
                            sftp.close()
                            st.session_state['agent_uploaded'] = True
                            st.session_state['agent_success_msgs'].append("runlist.json uploaded successfully!")
                            for k in ['agent_overwrite_confirm', 'agent_pending_file']:
                                if k in st.session_state:
                                    del st.session_state[k]
                            st.session_state['agent_step'] = 2
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Failed to upload runlist.json: {e}")
                            agent_reset_button()
                            st.stop()
                    elif uploaded_file is not None:
                        try:
                            file_bytes = uploaded_file.read()
                            ssh = st.session_state['agent_ssh']
                            sftp = ssh.open_sftp()
                            # 先檢查 /vmware/input 目錄是否存在
                            try:
                                sftp.stat('/vmware/input')
                            except FileNotFoundError:
                                sftp.close()
                                st.error("❌ This host is not a valid Agent VM. Directory /vmware/input does not exist.")
                                agent_reset_button()
                                st.stop()
                            # 檢查遠端是否已存在 runlist.json
                            file_exists = False
                            try:
                                sftp.stat('/vmware/input/runlist.json')
                                file_exists = True
                            except FileNotFoundError:
                                file_exists = False
                            if file_exists:
                                st.session_state['agent_pending_file'] = file_bytes
                                st.session_state['agent_overwrite_confirm'] = False
                                st.warning("runlist.json already exists on the remote host. Please confirm to overwrite.")
                                if st.button("Overwrite runlist.json on Agent", key="overwrite_btn", type="primary"):
                                    st.session_state['agent_overwrite_confirm'] = True
                                    st.rerun()
                                sftp.close()
                                st.stop()
                            else:
                                with sftp.file('/vmware/input/runlist.json', 'wb') as f:
                                    f.write(file_bytes)
                                sftp.close()
                                st.session_state['agent_uploaded'] = True
                                st.session_state['agent_success_msgs'].append("runlist.json uploaded successfully!")
                                for k in ['agent_overwrite_confirm', 'agent_pending_file']:
                                    if k in st.session_state:
                                        del st.session_state[k]
                                st.session_state['agent_step'] = 2
                                st.rerun()
                        except Exception as e:
                            st.error(f"❌ Failed to upload runlist.json: {e}")
                            agent_reset_button()
                            st.stop()
                    else:
                        st.warning("Please upload runlist.json to continue.")
                else:
                    # 已上傳成功，直接進入下一步
                    st.session_state['agent_step'] = 2
                    st.rerun()

        # 步驟 2: 檢查 internet 並 internal network config
        elif st.session_state['agent_step'] == 2:
            st.info("Checking Internet connectivity...")
            configurator = AgentConfigurator()
            ssh = st.session_state['agent_ssh']
            if not configurator.check_internet(ssh):
                st.error("❌ Internet connectivity check failed.")
                agent_reset_button()
                st.stop()
            st.session_state['agent_success_msgs'].append("Internet connectivity check successful.")
            st.session_state['agent_step'] = 3
            st.rerun()

        elif st.session_state['agent_step'] == 3:
            with st.spinner("Running AgentLauncher..."):
                ssh = st.session_state['agent_ssh']
                process = None  # 修正 Pylance undefined variable
                try:
                    stdin, stdout, stderr = ssh.exec_command("AgentLauncher -i")
                    progress_bar = st.progress(0)
                    progress_text = st.empty()
                    log_box = st.empty()
                    completed_layers = 0
                    total_layers = 0
                    log_lines = []
                    ovf_completed = False
                    firstboot_started = False
                    
                    for line in iter(stdout.readline, ''):
                        if line:
                            cleaned_line = line.strip()
                            log_lines.append(cleaned_line)
                            log_box.code('\n'.join(log_lines[-15:]), language="log") # Show last 15 lines

                            # Stage 2: Firstboot Scripts (50% -> 95%)
                            if 'Task: Run firstboot scripts' in cleaned_line and '(RUNNING' in cleaned_line:
                                firstboot_started = True
                                try:
                                    progress_part = cleaned_line.split('(RUNNING ')[1]
                                    firstboot_percent_str = progress_part.split('/100)')[0]
                                    firstboot_percent = int(firstboot_percent_str)
                                    # Map firstboot's 0-100% to overall 50-95%
                                    overall_percent = 50 + int(firstboot_percent * 0.45)
                                    progress_bar.progress(overall_percent)
                                    progress_text.text(f"Running firstboot scripts: {firstboot_percent}%")
                                except (ValueError, IndexError):
                                    pass # Ignore parsing errors
                            # OVF 完成過渡狀態
                            elif (('OVF Tool: Completed successfully' in cleaned_line or 'Transfer Completed' in cleaned_line) and not firstboot_started):
                                ovf_completed = True
                                progress_bar.progress(50)
                                progress_text.text("Appliance deployed. Waiting for vCenter to initialize...")
                            # Stage 1: OVF Deployment (0% -> 50%)
                            elif not ovf_completed and not firstboot_started and 'OVF Tool' in cleaned_line and 'Disk progress:' in cleaned_line:
                                try:
                                    percent_str = cleaned_line.split('Disk progress:')[1].strip().replace('%', '')
                                    ovf_percent = int(percent_str)
                                    overall_percent = int(ovf_percent * 0.5) # Map 0-100% to 0-50%
                                    progress_bar.progress(overall_percent)
                                    progress_text.text(f"Deploying appliance (OVF): {ovf_percent}%")
                                except (ValueError, IndexError):
                                    pass # Ignore parsing errors
                    
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        progress_bar.progress(100)
                        progress_text.text("Deployment successful!")
                        st.success("🎉 Agent deployment successful!")
                        st.session_state['agent_success_msgs'].append("All configurations have been completed!")
                        agent_ip = st.session_state['agent_form_data']['agent_ip']
                        st.session_state['agent_url'] = f"https://{agent_ip}/agent-ui"
                        st.session_state['agent_ssh'] = None
                        st.session_state['agent_step'] = 4
                        st.rerun()
                    else:
                        st.error(f"❌ Agent deployment failed with exit code: {exit_status}")
                        st.code('\n'.join(log_lines), language="log")
                    agent_reset_button()
                except Exception as e:
                    st.error(f"❌ Error running AgentLauncher: {e}")
                    agent_reset_button()
                    st.stop()

        elif st.session_state['agent_step'] == 4:
            # 只在完成步驟時顯示所有成功訊息
            for msg in st.session_state.get('agent_success_msgs', []):
                if msg == "All configurations have been completed!":
                    st.success("🎉 All configurations have been completed!")
                else:
                    st.success(msg)
            url = st.session_state.get('agent_url', None)
            if url:
                st.markdown(f"**Please open your browser and visit:** [{url}]({url}) for Agent web UI access.")
            agent_reset_button()
    elif choice == "Deploy vCenter":
        st.header(":blue[Deploy vCenter]")

        # Initialize session state
        if 'vc_step' not in st.session_state:
            st.session_state.vc_step = 0
        if 'vc_form_data' not in st.session_state:
            st.session_state.vc_form_data = {}
        if 'vc_temp_iso_path' not in st.session_state:
            st.session_state.vc_temp_iso_path = None
        if 'vc_si' not in st.session_state:
            st.session_state.vc_si = None
        if 'vc_deployment_network' not in st.session_state:
            st.session_state.vc_deployment_network = None
        if 'vc_success_msgs' not in st.session_state:
            st.session_state.vc_success_msgs = []
        
        c = VCConfigurator() # For getting defaults

        if st.session_state.vc_step == 0:
            st.info("""
            **Prerequisites**
            - Downloaded the VCSA image (.iso) and placed it on this machine
            - Added a DNS host record for the new vCenter VM on your DNS server
            """, icon="ℹ️")

            with st.form("vc_form"):
                st.subheader("1. VCSA ISO File Path")
                iso_path = st.text_input("Local path to VCSA ISO file", placeholder="e.g., C:\\Users\\Admin\\Downloads\\VMware-VCSA.iso")
                st.caption("In Windows, you can `Shift` + `Right-click` on the ISO file and select \"Copy as path\" to get the full file path.")
                # 自動去除頭尾空白與引號
                iso_path = iso_path.strip().strip('"').strip("'")

                st.subheader("2. Target ESXi Host (TC) Credentials")
                esxi_host = st.text_input("TC IP address", value=c.default_TC_host)
                esxi_username = st.text_input("TC username", value=c.default_TC_username)
                esxi_password = st.text_input("TC password", type="password", value=c.default_TC_password)
                esxi_datastore = st.text_input("TC datastore", value=c.default_TC_datastore)

                st.subheader("3. New vCenter Appliance Configuration")
                vm_name = st.text_input("vCenter VM name", placeholder="e.g., vcenter-01")
                vc_ip = st.text_input("vCenter IP address", placeholder="e.g., 192.168.10.50")
                vc_system_name = st.text_input("vCenter system name (FQDN)", placeholder="e.g., vc50.mty.com")
                vc_prefix = st.text_input("vCenter prefix", value=c.default_VC_prefix)
                vc_gateway = st.text_input("vCenter gateway", value=c.default_VC_gateway)
                vc_dns = st.text_input("vCenter DNS server(s)", value=c.default_VC_dns_servers)
                vc_ntp = st.text_input("vCenter NTP server(s)", value=c.default_VC_ntp_servers)
                vc_root_password = st.text_input("vCenter root password", type="password", value=c.default_VC_root_password)
                vc_sso_password = st.text_input("vCenter SSO password", type="password", value=c.default_VC_sso_password)

                submitted = st.form_submit_button("Next: Select Network", type="primary")

            if submitted:
                # 格式驗證
                def is_valid_ip(ip):
                    pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
                    if not re.match(pattern, ip):
                        return False
                    return all(0 <= int(part) <= 255 for part in ip.split('.'))
                def is_valid_fqdn(fqdn):
                    # 必須有至少兩個點（即三個 label）
                    if len(fqdn) > 253 or fqdn.count('.') < 2:
                        return False
                    labels = fqdn.split('.')
                    fqdn_pattern = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
                    return all(fqdn_pattern.match(label) for label in labels)

                # 取出欄位
                required_fields = [esxi_host, esxi_username, esxi_password, esxi_datastore, vm_name, vc_ip, vc_system_name, vc_prefix, vc_gateway, vc_dns, vc_ntp, vc_root_password, vc_sso_password]
                if not all(required_fields):
                    st.error("❌ Please fill in all required fields in the form.")
                    st.stop()
                # IP 檢查
                if not is_valid_ip(vc_ip):
                    st.error("❌ Invalid vCenter IP address format")
                    st.stop()
                if not is_valid_ip(vc_gateway):
                    st.error("❌ Invalid vCenter gateway format")
                    st.stop()
                # DNS/NTP 支援多個
                for ip in [x.strip() for x in vc_dns.split(',') if x.strip()]:
                    if not is_valid_ip(ip):
                        st.error(f"❌ Invalid vCenter DNS server format：{ip}")
                        st.stop()
                for ip in [x.strip() for x in vc_ntp.split(',') if x.strip()]:
                    if not is_valid_ip(ip):
                        st.error(f"❌ Invalid vCenter NTP server format：{ip}")
                        st.stop()
                # FQDN 檢查
                if not is_valid_fqdn(vc_system_name):
                    st.error("❌ Invalid vCenter system name (FQDN) format")
                    st.stop()
                if not os.path.exists(iso_path):
                    st.error("❌ ISO file not found at the specified path. Please check the path and try again.")
                    st.stop()
                
                st.session_state.vc_temp_iso_path = iso_path # Store the path directly
                st.session_state.vc_form_data = {
                    "esxi_host": esxi_host, "esxi_username": esxi_username, "esxi_password": esxi_password,
                    "esxi_datastore": esxi_datastore, "vm_name": vm_name, "vc_ip": vc_ip, "vc_system_name": vc_system_name,
                    "vc_prefix": vc_prefix, "vc_gateway": vc_gateway, "vc_dns": vc_dns.split(','), "vc_ntp": vc_ntp,
                    "vc_root_password": vc_root_password, "vc_sso_password": vc_sso_password
                }
                st.session_state.vc_step = 1
                st.rerun()

        elif st.session_state.vc_step == 1:
            with st.spinner("Connecting to ESXi host and fetching networks..."):
                data = st.session_state.vc_form_data
                connected, si = c.test_connection(data['esxi_host'], data['esxi_username'], data['esxi_password'])
                
                if not connected:
                    st.error("❌ Failed to connect to ESXi host. Please check credentials and network.")
                    vc_reset_button()
                    st.stop()
                
                st.session_state.vc_si = si
                networks = c.get_available_networks(si)
                if not networks:
                    st.error("❌ No networks found on the ESXi host.")
                    vc_reset_button()
                    st.stop()
            
            st.success("✅ Connected to ESXi host successfully.")
            st.subheader("Select vCenter Deployment Network")
            deployment_network = st.selectbox("Available networks on ESXi host:", options=networks)
            
            if st.button("Next: Review and Deploy", type="primary"):
                st.session_state.vc_deployment_network = deployment_network
                st.session_state.vc_step = 2
                st.rerun()

        elif st.session_state.vc_step == 2:
            st.subheader("Deployment Summary")
            data = st.session_state.vc_form_data
            st.json({
                "Target ESXi Host": data['esxi_host'],
                "vCenter VM Name": data['vm_name'],
                "vCenter IP": data['vc_ip'],
                "Deployment Network": st.session_state.vc_deployment_network
            })
            # 動態組裝 JSON 預覽與下載
            import json as _json
            config = {
                "__version": "2.13.0",
                "new_vcsa": {
                    "esxi": {
                        "hostname": data['esxi_host'],
                        "username": data['esxi_username'],
                        "password": data['esxi_password'],
                        "deployment_network": st.session_state.vc_deployment_network,
                        "datastore": data['esxi_datastore']
                    },
                    "appliance": {
                        "thin_disk_mode": True,
                        "deployment_option": "medium",
                        "name": data['vm_name']
                    },
                    "network": {
                        "ip_family": "ipv4",
                        "mode": "static",
                        "ip": data['vc_ip'],
                        "prefix": data['vc_prefix'],
                        "gateway": data['vc_gateway'],
                        "dns_servers": data['vc_dns'],
                        "system_name": data['vc_system_name']
                    },
                    "os": {
                        "password": data['vc_root_password'],
                        "ntp_servers": data['vc_ntp'],
                        "ssh_enable": True
                    },
                    "sso": {
                        "password": data['vc_sso_password'],
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
            json_str = _json.dumps(config, indent=2)
            with st.expander('Show full deployment JSON'):
                st.code(json_str, language='json')
                st.download_button(
                    label='Download vcsa_deployment.json',
                    data=json_str,
                    file_name='vcsa_deployment.json',
                    mime='application/json'
                )
            st.warning("Deployment will start after clicking the button. This process is time-consuming and **Windows-specific** (requires PowerShell). Please do not navigate away.", icon="⚠️")

            if st.button("Confirm and Deploy vCenter", type="primary"):
                st.session_state.vc_step = 3
                st.rerun()
        
        elif st.session_state.vc_step == 3:
            data = st.session_state.vc_form_data
            iso_path = st.session_state.vc_temp_iso_path
            deployment_network = st.session_state.vc_deployment_network
            template_path = os.path.join(os.getcwd(), "vcsa_deployment.json")
            mount_drive = None
            process = None  # 修正 Pylance undefined variable
            try:
                with st.spinner("Mounting VCSA ISO... (This may require administrator privileges)"):
                    mount_drive = c.mount_iso(iso_path)
                    if not mount_drive:
                        st.error("❌ Failed to mount ISO. Ensure you are on Windows and have permissions.")
                        vc_reset_button()
                        st.stop()
                st.success(f"✅ ISO mounted to drive: {mount_drive}")

                vcsa_deploy_path = c.get_vcsa_deploy_path(mount_drive)
                
                c.create_json_template(data['esxi_host'], data['esxi_username'], data['esxi_password'], template_path, data['vm_name'], deployment_network)
                with open(template_path, 'r') as f: config = json.load(f)
                
                config['new_vcsa']['network'].update({
                    'ip': data['vc_ip'], 'prefix': data['vc_prefix'], 'gateway': data['vc_gateway'],
                    'dns_servers': data['vc_dns'], 'system_name': data['vc_system_name']
                })
                config['new_vcsa']['os'].update({'password': data['vc_root_password'], 'ntp_servers': data['vc_ntp']})
                config['new_vcsa']['sso']['password'] = data['vc_sso_password']
                
                with open(template_path, 'w') as f: json.dump(config, f, indent=2)

                with st.spinner("Starting vCenter deployment... This will take a long time."):
                    progress_bar = st.progress(0)
                    progress_text = st.empty()
                    log_box = st.code("", language="log")
                    
                    cmd = [vcsa_deploy_path, 'install', template_path, '--accept-eula', '--no-ssl-certificate-verification', '--acknowledge-ceip']
                    
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
                    
                    log_lines = []
                    ovf_completed = False
                    firstboot_started = False
                    
                    for line in iter(process.stdout.readline, ''):
                        if line:
                            cleaned_line = line.strip()
                            log_lines.append(cleaned_line)
                            log_box.code('\n'.join(log_lines[-15:]), language="log") # Show last 15 lines

                            # Stage 2: Firstboot Scripts (50% -> 95%)
                            if 'Task: Run firstboot scripts' in cleaned_line and '(RUNNING' in cleaned_line:
                                firstboot_started = True
                                try:
                                    progress_part = cleaned_line.split('(RUNNING ')[1]
                                    firstboot_percent_str = progress_part.split('/100)')[0]
                                    firstboot_percent = int(firstboot_percent_str)
                                    # Map firstboot's 0-100% to overall 50-95%
                                    overall_percent = 50 + int(firstboot_percent * 0.45)
                                    progress_bar.progress(overall_percent)
                                    progress_text.text(f"Running firstboot scripts: {firstboot_percent}%")
                                except (ValueError, IndexError):
                                    pass # Ignore parsing errors
                            # OVF 完成過渡狀態
                            elif (('OVF Tool: Completed successfully' in cleaned_line or 'Transfer Completed' in cleaned_line) and not firstboot_started):
                                ovf_completed = True
                                progress_bar.progress(50)
                                progress_text.text("Appliance deployed. Waiting for vCenter to initialize...")
                            # Stage 1: OVF Deployment (0% -> 50%)
                            elif not ovf_completed and not firstboot_started and 'OVF Tool' in cleaned_line and 'Disk progress:' in cleaned_line:
                                try:
                                    percent_str = cleaned_line.split('Disk progress:')[1].strip().replace('%', '')
                                    ovf_percent = int(percent_str)
                                    overall_percent = int(ovf_percent * 0.5) # Map 0-100% to 0-50%
                                    progress_bar.progress(overall_percent)
                                    progress_text.text(f"Deploying appliance (OVF): {ovf_percent}%")
                                except (ValueError, IndexError):
                                    pass # Ignore parsing errors
                    
                    process.wait()
                    if process.returncode == 0:
                        progress_bar.progress(100)
                        progress_text.text("Deployment successful!")
                        st.success("🎉 vCenter deployment successful!")
                        # 查詢 ESXi 上建立時間最新的 VM
                        content = st.session_state.vc_si.RetrieveContent()
                        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                        vms = list(container.view)
                        container.Destroy()
                        if not vms:
                            st.error("No VMs found on ESXi host.")
                            vc_reset_button()
                        else:
                            latest_vm = max(vms, key=lambda vm: getattr(vm.config, 'createDate', 0) or 0)
                            st.session_state['ovf_latest_vm_name'] = latest_vm.name
                            st.session_state['vc_step'] = 4
                            st.rerun()
                    else:
                        st.error(f"❌ vCenter deployment failed with exit code: {process.returncode}")
                        st.code('\n'.join(log_lines), language="log")
                        vc_reset_button()

            except Exception as e:
                st.error(f"❌ An unexpected error occurred: {e}")
                vc_reset_button()
                st.stop()
            finally:
                if mount_drive:
                    c.unmount_iso(mount_drive, iso_path)
                # No longer need to clean up temp file here as we are using the original path
                if 'vc_step' in st.session_state and st.session_state.vc_step != 4:
                    vc_reset_button() # Reset if failed
                else:
                    st.rerun()

        elif st.session_state.vc_step == 4:
            data = st.session_state.vc_form_data
            url_management = f"https://{data['vc_system_name']}:5480"
            url_vcsa = f"https://{data['vc_system_name']}"
            
            st.balloons()
            st.success("🎉 All configurations have been completed!")
            st.markdown(f"""
            Ensure the jump server is on the vCenter network, then visit:
            - **vCenter Server Management UI:** [{url_management}]({url_management})
            - **vCenter Client UI:** [{url_vcsa}]({url_vcsa})
            
            Login with user `administrator@vsphere.local` and password `{data['vc_sso_password']}`.
            """)
            vc_reset_button()
    elif choice == "Deploy/Export OVF":
        st.header(":blue[Deploy/Export OVF]")
        st.info(
            """
            **Prerequisites**
            - Installed [VMware OVF Tool](https://developer.broadcom.com/tools/open-virtualization-format-ovf-tool/latest) on this machine
            - Obtained the IP address of the target ESXi host
            """, icon="ℹ️"
        )
        # Determine if an operation is in progress to disable the radio button
        deploying_ovf = (st.session_state.get('ovf_step') == 3 and st.session_state.get('ovf_mode') == 'Deploy OVF')
        exporting_ovf = (st.session_state.get('ovf_step') == 3 and st.session_state.get('ovf_mode') == 'Export OVF')
        options = ["Deploy OVF", "Export OVF", "Delete VM"]

        # Set default index for radio button, ensures the selection is sticky
        try:
            current_mode_index = options.index(st.session_state.get('ovf_mode', 'Deploy OVF'))
        except ValueError:
            current_mode_index = 0

        # This single radio call handles all cases.
        # It always shows all options. The 'disabled' flag greys them out when busy.
        is_disabled = deploying_ovf or exporting_ovf
        selected_mode = st.radio(
            "Select operation",
            options,
            index=current_mode_index,
            disabled=is_disabled,
            horizontal=True
        )

        # If the user changes the radio button, reset the entire OVF state
        if 'ovf_mode' not in st.session_state or st.session_state.ovf_mode != selected_mode:
            for k in list(st.session_state.keys()):
                if k.startswith('ovf_'):
                    del st.session_state[k]
            st.session_state['ovf_mode'] = selected_mode
            st.rerun()

        # Use the mode from session state as the source of truth
        ovf_mode = st.session_state.ovf_mode

        # Display info message if an operation is in progress
        if deploying_ovf:
            st.info("OVF deployment in progress. Please wait until it completes before switching operation.")
        elif exporting_ovf:
            st.info("OVF export in progress. Please wait until it completes before switching operation.")

        # Session state for multi-step flows
        if 'ovf_step' not in st.session_state:
            st.session_state['ovf_step'] = 0
        if 'ovf_form_data' not in st.session_state:
            st.session_state['ovf_form_data'] = {}
        if 'ovf_si' not in st.session_state:
            st.session_state['ovf_si'] = None
        if 'ovf_success_msgs' not in st.session_state:
            st.session_state['ovf_success_msgs'] = []
        if 'ovf_vm_list' not in st.session_state:
            st.session_state['ovf_vm_list'] = []
        if 'ovf_networks' not in st.session_state:
            st.session_state['ovf_networks'] = []
        if 'ovf_selected_vm' not in st.session_state:
            st.session_state['ovf_selected_vm'] = None
        if 'ovf_progress' not in st.session_state:
            st.session_state['ovf_progress'] = 0
        if 'ovf_log_lines' not in st.session_state:
            st.session_state['ovf_log_lines'] = []
        if 'ovf_latest_vm_name' not in st.session_state:
            st.session_state['ovf_latest_vm_name'] = None

        def ovf_reset_button():
            if st.button("Reset/Restart"):
                # Clean up temporary file if it exists from a previous run
                temp_path = st.session_state.get('ovf_temp_path')
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                        st.info(f"Cleaned up temporary file: {temp_path}")
                    except OSError as e:
                        st.warning(f"Could not remove temporary file {temp_path}: {e}")

                for k in ['ovf_step','ovf_form_data','ovf_si','ovf_success_msgs','ovf_vm_list','ovf_networks','ovf_selected_vm','ovf_progress','ovf_log_lines', 'ovf_latest_vm_name', 'ovf_temp_path', 'ovf_export_path_result']:
                    if k in st.session_state:
                        del st.session_state[k]
                st.rerun()

        # Deploy OVF
        if ovf_mode == "Deploy OVF":
            c = OVFManager()
            if st.session_state['ovf_step'] == 0:
                with st.form("ovf_deploy_form"):
                    ovf_path = st.text_input("Path to OVF/OVA file", placeholder="e.g., C:\\Users\\Admin\\Downloads\\TEST.ova")
                    st.caption("In Windows, you can `Shift` + `Right-click` on the file and select \"Copy as path\" to get the full file path.")
                    # 自動去除頭尾空白與引號
                    ovf_path = ovf_path.strip().strip('"').strip("'")
                    esxi_host = st.text_input("ESXi Host IP address")
                    esxi_username = st.text_input("ESXi username", value="root")
                    esxi_password = st.text_input("ESXi password", type="password", value="Passw0rd!")
                    esxi_datastore = st.text_input("ESXi datastore", value="datastore1")
                    submitted = st.form_submit_button("Next: Connect & Select Network", type="primary")

                if submitted:
                    if not ovf_path:
                        st.error("❌ Please provide the path to the OVF/OVA file on the server.")
                        st.stop()
                    
                    if not os.path.exists(ovf_path):
                        st.error(f"❌ File not found at the specified server path: {ovf_path}")
                        st.stop()

                    if not all([esxi_host, esxi_username, esxi_password, esxi_datastore]):
                        st.error("❌ Please fill in all required fields in the form.")
                        st.stop()
                    
                    if not c.validate_ip(esxi_host):
                        st.error("❌ Invalid ESXi Host IP format.")
                        st.stop()
                    
                    connected, si = c.test_connection(esxi_host, esxi_username, esxi_password)
                    if not connected:
                        st.error("❌ Failed to connect to ESXi host. Please check credentials and network.")
                        ovf_reset_button()
                        st.stop()
                    
                    networks = c.get_available_networks(si)
                    if not networks:
                        st.error("❌ No networks found on ESXi host.")
                        ovf_reset_button()
                        st.stop()
                    
                    st.session_state['ovf_form_data'] = {
                        'ovf_path': ovf_path, # Use the direct server-side path
                        'esxi_host': esxi_host, 
                        'esxi_username': esxi_username,
                        'esxi_password': esxi_password, 
                        'esxi_datastore': esxi_datastore
                    }
                    st.session_state['ovf_si'] = si
                    st.session_state['ovf_networks'] = networks
                    st.session_state['ovf_step'] = 1
                    st.rerun()
            elif st.session_state['ovf_step'] == 1:
                # 取得 OVF networks
                c = OVFManager()
                ovf_path = st.session_state['ovf_form_data']['ovf_path']
                ovf_networks = c.get_ovf_networks(ovf_path)
                networks = st.session_state['ovf_networks']
                st.subheader("Map OVF Networks to ESXi Networks")
                mapping = {}
                for ovf_net in ovf_networks:
                    mapping[ovf_net] = st.selectbox(f"OVF network '{ovf_net}' maps to:", options=networks, key=f"ovfmap_{ovf_net}")
                vm_name = st.text_input("Target VM name (leave blank to use default from OVF)")
                if st.button("Next: Review & Deploy", type="primary"):
                    st.session_state['ovf_form_data']['network_mapping'] = mapping
                    st.session_state['ovf_form_data']['vm_name'] = vm_name
                    st.session_state['ovf_step'] = 2
                    st.rerun()
            elif st.session_state['ovf_step'] == 2:
                data = st.session_state['ovf_form_data']
                st.subheader("Deployment Summary")
                st.json({
                    "ESXi Host": data['esxi_host'],
                    "OVF/OVA file": data['ovf_path'],
                    "Datastore": data['esxi_datastore'],
                    "Network Mapping": data['network_mapping'],
                    "VM Name": data['vm_name'] or "(default from OVF)"
                })
                st.warning("Deployment will start after clicking the button. Please do not navigate away.", icon="⚠️")
                if st.button("Confirm and Deploy OVF", type="primary"):
                    st.session_state['ovf_step'] = 3
                    st.rerun()
            elif st.session_state['ovf_step'] == 3:
                # 執行部署
                c = OVFManager()
                data = st.session_state['ovf_form_data']
                si = st.session_state['ovf_si']
                ovf_path = data['ovf_path']
                esxi_host = data['esxi_host']
                esxi_username = data['esxi_username']
                esxi_password = data['esxi_password']
                esxi_datastore = data['esxi_datastore']
                mapping = data['network_mapping']
                vm_name = data['vm_name']
                with st.spinner("Deploying OVF... This may take a while."):
                    progress_bar = st.progress(0)
                    log_box = st.code("", language="log")
                    # 組裝 ovftool 命令
                    net_args = [f'--net:{k}={v}' for k, v in mapping.items()]
                    cmd = [c.ovf_tool_path, '--noSSLVerify', '--acceptAllEulas', '--X:logLevel=verbose',
                           f'--datastore={esxi_datastore}']
                    if vm_name:
                        cmd.append(f'--name={vm_name}')
                    cmd += net_args + [ovf_path, f'vi://{esxi_username}:{esxi_password}@{esxi_host}']
                    import subprocess
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
                    log_lines = []
                    for line in iter(process.stdout.readline, ''):
                        if line:
                            log_lines.append(line.strip())
                            log_box.code('\n'.join(log_lines[-15:]), language="log")
                            # 進度條解析
                            if 'Disk progress:' in line:
                                try:
                                    percent = int(line.split('Disk progress:')[1].strip().replace('%',''))
                                    progress_bar.progress(percent)
                                except:
                                    pass
                    process.wait()
                    if process.returncode == 0:
                        progress_bar.progress(100)
                        st.balloons()
                        st.success("🎉 OVF deployment successful!")
                        # 查詢 ESXi 上建立時間最新的 VM
                        content = st.session_state.ovf_si.RetrieveContent()
                        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                        vms = list(container.view)
                        container.Destroy()
                        if not vms:
                            st.error("No VMs found on ESXi host.")
                            ovf_reset_button()
                        else:
                            latest_vm = max(vms, key=lambda vm: getattr(vm.config, 'createDate', 0) or 0)
                            st.session_state['ovf_latest_vm_name'] = latest_vm.name
                            st.session_state['ovf_step'] = 4
                            st.rerun()
                    else:
                        st.error(f"❌ OVF deployment failed with exit code: {process.returncode}")
                        st.code('\n'.join(log_lines), language="log")
                        ovf_reset_button()
            elif st.session_state['ovf_step'] == 4:
                si = st.session_state['ovf_si']
                vm_name = st.session_state.get('ovf_latest_vm_name')

                if not vm_name:
                    st.error("No VM info found.")
                else:
                    content = si.RetrieveContent()
                    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                    vm = next((v for v in list(container.view) if v.name == vm_name), None)
                    container.Destroy()

                    if not vm:
                        st.error(f"VM '{vm_name}' not found after deployment.")
                    else:
                        st.info(f"Successfully deployed VM: **{vm_name}**")
                        
                        # More robustly check the power state by converting to a string
                        if str(vm.runtime.powerState) == 'poweredOff':
                            if st.button(f"Power on VM '{vm.name}'", type="primary"):
                                with st.spinner(f"Powering on VM '{vm.name}'..."):
                                    try:
                                        task = vm.PowerOnVM_Task()
                                        # Wait for the task to complete
                                        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                                            time.sleep(1)
                                        if task.info.state == vim.TaskInfo.State.success:
                                            st.success(f"VM '{vm.name}' powered on successfully!")
                                        else:
                                            st.error(f"Failed to power on VM: {task.info.error}")
                                    except Exception as e:
                                        st.error(f"An error occurred while powering on: {e}")
                                
                                # Rerun to refresh the state display
                                time.sleep(2)
                                st.rerun()
                        else:
                            st.success(f"VM '{vm.name}' is currently: {vm.runtime.powerState}")

                ovf_reset_button()
        # Export OVF
        elif ovf_mode == "Export OVF":
            c = OVFManager()
            if st.session_state['ovf_step'] == 0:
                with st.form("ovf_export_form"):
                    esxi_host = st.text_input("ESXi Host IP address")
                    esxi_username = st.text_input("ESXi username", value="root")
                    esxi_password = st.text_input("ESXi password", type="password", value="Passw0rd!")
                    submitted = st.form_submit_button("Next: Connect & Select VM", type="primary")
                if submitted:
                    if not all([esxi_host, esxi_username, esxi_password]):
                        st.error("❌ Please fill in all required fields in the form.")
                        st.stop()
                    if not c.validate_ip(esxi_host):
                        st.error("❌ Invalid ESXi Host IP format.")
                        st.stop()
                    connected, si = c.test_connection(esxi_host, esxi_username, esxi_password)
                    if not connected:
                        st.error("❌ Failed to connect to ESXi host. Please check credentials and network.")
                        ovf_reset_button()
                        st.stop()
                    vm_list = c.list_vms(si)
                    if not vm_list:
                        st.error("❌ No VMs found on ESXi host.")
                        ovf_reset_button()
                        st.stop()
                    st.session_state['ovf_form_data'] = {
                        'esxi_host': esxi_host, 'esxi_username': esxi_username, 'esxi_password': esxi_password
                    }
                    st.session_state['ovf_si'] = si
                    st.session_state['ovf_vm_list'] = vm_list
                    st.session_state['ovf_step'] = 1
                    st.rerun()
            elif st.session_state['ovf_step'] == 1:
                # This widget is outside the form, so its changes trigger immediate reruns
                vm_list = st.session_state['ovf_vm_list']
                if not vm_list:
                    st.warning("No VMs found on the host.")
                    ovf_reset_button()
                    st.stop()

                selected_vm = st.selectbox(
                    "Select VM to export:", 
                    options=vm_list,
                    key='ovf_export_vm_selection' # A unique key to hold the selection
                )

                with st.form("ovf_export_details_form"):
                    export_dir = st.text_input(
                        "Local directory to save OVA file", 
                        placeholder="e.g., C:\\Users\\Admin\\Downloads"
                    )
                    st.caption("Please provide the path to the folder where the OVA file will be saved.")

                    # This widget is inside the form. Its value is populated from session_state
                    # but the user can edit it. The final value is retrieved on submit.
                    if st.session_state.ovf_export_vm_selection:
                        default_filename = st.session_state.ovf_export_vm_selection.replace(" ", "_")
                    else:
                        default_filename = ""

                    output_filename = st.text_input(
                        "Enter output file name (without .ova extension)", 
                        value=default_filename
                    )

                    submitted = st.form_submit_button("Next: Review & Export", type="primary")
                
                if submitted:
                    # On submit, 'selected_vm' is from the widget outside the form (via session state)
                    # and 'output_filename' is from the widget inside the form.
                    if not all([st.session_state.ovf_export_vm_selection, export_dir, output_filename]):
                        st.error("❌ Please fill in all required fields in the form.")
                        st.stop()

                    final_filename = f"{output_filename}.ova"
                    full_export_path = os.path.join(export_dir, final_filename)
                    
                    st.session_state['ovf_form_data']['selected_vm'] = st.session_state.ovf_export_vm_selection
                    st.session_state['ovf_form_data']['export_path'] = full_export_path
                    st.session_state['ovf_step'] = 2
                    st.rerun()
            elif st.session_state['ovf_step'] == 2:
                data = st.session_state['ovf_form_data']
                export_path = data.get('export_path')

                st.subheader("Export Summary")
                st.json({
                    "ESXi Host": data['esxi_host'],
                    "VM to export": data['selected_vm'],
                    "Export path": export_path
                })
                
                # Check if the file already exists and show a warning
                if export_path and os.path.exists(export_path):
                    st.warning(f"**File already exists!**\n\nThe file at `{export_path}` already exists and will be overwritten.", icon="⚠️")

                st.info("Export will start after clicking the button. Please do not navigate away.")
                
                if st.button("Confirm and Export OVF", type="primary"):
                    st.session_state['ovf_step'] = 3
                    st.rerun()
            elif st.session_state['ovf_step'] == 3:
                c = OVFManager()
                data = st.session_state['ovf_form_data']
                si = st.session_state['ovf_si']
                esxi_host = data['esxi_host']
                esxi_username = data['esxi_username']
                esxi_password = data['esxi_password']
                selected_vm = data['selected_vm']
                with st.spinner("Exporting OVF... This may take a while."):
                    progress_bar = st.progress(0)
                    log_box = st.code("", language="log")
                    cmd = [c.ovf_tool_path, '--noSSLVerify', '--acceptAllEulas', '--overwrite', '--X:logLevel=verbose',
                           f'vi://{esxi_username}:{esxi_password}@{esxi_host}/{selected_vm}', data['export_path']]
                    
                    import subprocess
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
                    log_lines = []
                    for line in iter(process.stdout.readline, ''):
                        if line:
                            log_lines.append(line.strip())
                            log_box.code('\n'.join(log_lines[-15:]), language="log")
                            if 'Disk progress:' in line:
                                try:
                                    percent = int(line.split('Disk progress:')[1].strip().replace('%',''))
                                    progress_bar.progress(percent)
                                except:
                                    pass
                    process.wait()
                    if process.returncode == 0:
                        progress_bar.progress(100)
                        st.session_state['ovf_export_path_result'] = data['export_path']
                        st.session_state['ovf_step'] = 5 # Use a new step number to avoid conflict with deploy
                        st.rerun()
                    else:
                        st.error(f"❌ OVF export failed with exit code: {process.returncode}")
                        st.code('\n'.join(log_lines), language="log")
                        ovf_reset_button()

            elif st.session_state['ovf_step'] == 5: # New step for export success
                st.balloons()
                st.success("🎉 OVF export successful!")
                export_path = st.session_state.get('ovf_export_path_result')
                if export_path:
                    st.markdown("**File saved to:**")
                    st.code(export_path, language='text')
                ovf_reset_button()
        # Delete VM
        elif ovf_mode == "Delete VM":
            c = OVFManager()
            if st.session_state['ovf_step'] == 0:
                with st.form("ovf_delete_form"):
                    esxi_host = st.text_input("ESXi Host IP address")
                    esxi_username = st.text_input("ESXi username", value="root")
                    esxi_password = st.text_input("ESXi password", type="password", value="Passw0rd!")
                    submitted = st.form_submit_button("Next: Connect & Select VM", type="primary")
                if submitted:
                    if not all([esxi_host, esxi_username, esxi_password]):
                        st.error("❌ Please fill in all required fields in the form.")
                        st.stop()
                    if not c.validate_ip(esxi_host):
                        st.error("❌ Invalid ESXi Host IP format.")
                        st.stop()
                    connected, si = c.test_connection(esxi_host, esxi_username, esxi_password)
                    if not connected:
                        st.error("❌ Failed to connect to ESXi host. Please check credentials and network.")
                        ovf_reset_button()
                        st.stop()
                    vm_list = c.list_vms(si)
                    if not vm_list:
                        st.error("❌ No VMs found on ESXi host.")
                        ovf_reset_button()
                        st.stop()
                    st.session_state['ovf_form_data'] = {
                        'esxi_host': esxi_host, 'esxi_username': esxi_username, 'esxi_password': esxi_password
                    }
                    st.session_state['ovf_si'] = si
                    st.session_state['ovf_vm_list'] = vm_list
                    st.session_state['ovf_step'] = 1
                    st.rerun()
            elif st.session_state['ovf_step'] == 1:
                vm_list = st.session_state['ovf_vm_list']
                selected_vm = st.selectbox("Select VM to delete:", options=vm_list)
                if st.button("Next: Review & Delete", type="primary"):
                    if not selected_vm:
                        st.error("❌ Please select a VM to delete.")
                        st.stop()
                    st.session_state['ovf_form_data']['selected_vm'] = selected_vm
                    st.session_state['ovf_step'] = 2
                    st.rerun()
            elif st.session_state['ovf_step'] == 2:
                data = st.session_state['ovf_form_data']
                si = st.session_state['ovf_si']
                selected_vm_name = data['selected_vm']
                
                st.subheader("Delete Summary")
                st.json({
                    "ESXi Host": data['esxi_host'],
                    "VM to delete": selected_vm_name
                })

                # Check VM power state
                try:
                    content = si.RetrieveContent()
                    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                    vm_to_check = next((v for v in list(container.view) if v.name == selected_vm_name), None)
                    container.Destroy()
                    if vm_to_check and vm_to_check.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                        st.warning(f"⚠️ The VM '{selected_vm_name}' is currently powered on. It will be automatically powered off before deletion.")
                except Exception as e:
                    st.warning(f"Could not check VM power state: {e}")
                
                st.error("This action is irreversible and will permanently delete the VM.", icon="🚨")

                if st.button("Confirm and Delete VM", type="primary"):
                    st.session_state['ovf_step'] = 3
                    st.rerun()

            elif st.session_state['ovf_step'] == 3:
                data = st.session_state['ovf_form_data']
                si = st.session_state['ovf_si']
                selected_vm = data['selected_vm']
                
                with st.spinner(f"Deleting VM '{selected_vm}'... This may take a while."):
                    log_lines = []
                    log_box = st.code('\n'.join(log_lines), language="log")
                    
                    try:
                        content = si.RetrieveContent()
                        container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                        vm_to_delete = next((v for v in list(container.view) if v.name == selected_vm), None)
                        container.Destroy()

                        if not vm_to_delete:
                            st.error(f"VM '{selected_vm}' not found.")
                            ovf_reset_button()
                            st.stop()

                        # Power off if necessary
                        if vm_to_delete.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                            log_lines.append(f"VM is powered on. Attempting to power off...")
                            log_box.code('\n'.join(log_lines), language="log")
                            task = vm_to_delete.PowerOffVM_Task()
                            while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                                time.sleep(1)
                            
                            if task.info.state == vim.TaskInfo.State.error:
                                st.error(f"Failed to power off VM before deletion: {task.info.error.msg}")
                                ovf_reset_button()
                                st.stop()
                            log_lines.append("VM powered off successfully.")
                            log_box.code('\n'.join(log_lines), language="log")

                        # Delete the VM
                        log_lines.append("Sending delete command...")
                        log_box.code('\n'.join(log_lines), language="log")
                        task = vm_to_delete.Destroy_Task()
                        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                            time.sleep(1)
                        
                        if task.info.state == vim.TaskInfo.State.success:
                            log_lines.append("VM deleted from host.")
                            log_box.code('\n'.join(log_lines), language="log")
                            st.success("🎉 VM deleted successfully!")
                        else:
                            st.error(f"❌ VM deletion failed: {task.info.error.msg}")

                    except Exception as e:
                        st.error(f"❌ An error occurred during deletion: {e}")
                    
                    ovf_reset_button()
    elif choice == "Manage DNS host record":
        st.header(":blue[Manage DNS host record]")
        st.info("""
        **Prerequisites**
        - SSH service is enabled and running on the Windows DNS server
        """, icon="ℹ️")

        # Session state for DNS management
        DNS_RESET_KEYS = ['dns_step', 'dns_form_data', 'dns_ssh', 'dns_records', 'dns_zone_to_display']
        for key in DNS_RESET_KEYS:
            if key not in st.session_state:
                st.session_state[key] = None if key != 'dns_step' else 0

        def dns_reset_button():
            if st.button("Reset/Restart"):
                for k in DNS_RESET_KEYS:
                    if k in st.session_state:
                        del st.session_state[k]
                st.rerun()

        c = DNSConfigurator()

        form_col, _ = st.columns([2, 1])
        with form_col:
            if st.session_state.dns_step == 0:
                with st.form("dns_connect_form"):
                    st.subheader("1. Connect to DNS Server")
                    dns_server = st.text_input("DNS server IP", value=c.default_dns_server)
                    username = st.text_input("Username", value=c.username)
                    password = st.text_input("Password", type="password", value=c.password)
                    submitted = st.form_submit_button("Connect and Manage DNS", type="primary")
                if submitted:
                    if not all([dns_server, username, password]):
                        st.error("❌ Please fill in all required fields.")
                        st.stop()
                    with st.spinner("Connecting to DNS server..."):
                        ssh = c.ssh_connect(dns_server, username, password)
                        if not ssh:
                            st.error("❌ SSH connection failed. Please check IP/credentials and SSH status.")
                            st.stop()
                    st.session_state.dns_ssh = ssh
                    st.session_state.dns_form_data = {'dns_server': dns_server, 'username': username, 'password': password}
                    st.session_state.dns_step = 1
                    st.rerun()

            elif st.session_state.dns_step == 1:
                st.success(f"✅ Connected to DNS server: {st.session_state.dns_form_data['dns_server']}")
                add_tab, delete_tab = st.tabs(["Add DNS Record", "Delete DNS Record"])
                with add_tab:
                    with st.form("add_dns_record_form"):
                        st.subheader("Add a new A record")
                        add_zone = st.text_input("DNS Zone", value=c.default_zone, key="add_zone")
                        add_hostname = st.text_input("Hostname (without domain)", key="add_hostname")
                        add_ip = st.text_input("IP Address", key="add_ip")
                        add_submitted = st.form_submit_button("Add Record")
                    if add_submitted:
                        if not all([add_zone, add_hostname, add_ip]):
                            st.error("❌ Please fill in all fields for adding a record.")
                        elif not c.validate_ip(add_ip):
                            st.error("❌ Invalid IP address format.")
                        else:
                            with st.spinner(f"Adding record {add_hostname}.{add_zone}..."):
                                success = c.add_dns_host(st.session_state.dns_ssh, add_zone, add_hostname, add_ip)
                                if success:
                                    st.toast(f"✅ Successfully added record for {add_hostname}", icon="🎉")
                                    st.session_state.dns_records = None 
                                else:
                                    st.error("❌ Failed to add DNS record. Check logs for details.")
                with delete_tab:
                    st.subheader("Delete an existing A record")
                    del_zone = st.text_input("DNS Zone", value=c.default_zone, key="del_zone")
                    if st.button("Fetch Records for Deletion", key="fetch_del_records"):
                        with st.spinner(f"Fetching records from zone {del_zone}..."):
                            st.session_state.dns_records_for_delete = c.get_and_display_dns_records(st.session_state.dns_ssh, del_zone, display_mode="json", display_header=False)
                    if st.session_state.get('dns_records_for_delete'):
                        records = st.session_state.dns_records_for_delete
                        if records:
                            record_options = {f"{r.get('HostName', 'N/A')} ({r.get('IPAddress', 'N/A')})": r.get('HostName') for r in records}
                            display_choice = st.selectbox("Select record to delete", options=record_options.keys())
                            if st.button("Delete Selected Record", type="primary"):
                                hostname_to_delete = record_options[display_choice]
                                with st.spinner(f"Deleting record {hostname_to_delete}..."):
                                    success = c.delete_dns_host(st.session_state.dns_ssh, del_zone, hostname_to_delete)
                                    if success:
                                        st.toast(f"✅ Successfully deleted {hostname_to_delete}", icon="🗑️")
                                        st.session_state.dns_records = None
                                        st.session_state.dns_records_for_delete = None
                                        st.rerun()
                                    else:
                                        st.error("❌ Failed to delete DNS record.")
                        else:
                            st.warning("No A records found in this zone to delete.")
                st.divider()
                st.subheader("View Records in a Zone")
                if st.session_state.dns_zone_to_display is None:
                    st.session_state.dns_zone_to_display = c.default_zone
                with st.form("view_zone_form"):
                    zone_to_display = st.text_input("DNS Zone to display", value=st.session_state.dns_zone_to_display)
                    view_submitted = st.form_submit_button("View Records")
                if view_submitted:
                    st.session_state.dns_zone_to_display = zone_to_display
                    st.session_state.dns_records = None # Force refetch
                    st.rerun()
                with st.spinner(f"Fetching records for zone '{st.session_state.dns_zone_to_display}'..."):
                    records = c.get_and_display_dns_records(st.session_state.dns_ssh, st.session_state.dns_zone_to_display, display_mode="json", display_header=False)
                    if records:
                        df = pd.DataFrame(records)
                        st.dataframe(df, use_container_width=True)
                    else:
                        st.info(f"No A records found in zone '{st.session_state.dns_zone_to_display}'.")
                dns_reset_button()
    elif choice == "Enable PCI passthrough for NVIDIA GPU":
        st.header(":blue[Enable PCI passthrough for NVIDIA GPU]")
        st.info("""
        **Prerequisites**
        - Installed NVIDIA GPU on the target ESXi host
        - Obtained the IP address of the target ESXi host
        """, icon="ℹ️")

        # Session state for multi-step wizard
        if 'pci_step' not in st.session_state:
            st.session_state['pci_step'] = 0
        if 'pci_form_data' not in st.session_state:
            st.session_state['pci_form_data'] = {}
        if 'pci_si' not in st.session_state:
            st.session_state['pci_si'] = None
        if 'pci_vm_list' not in st.session_state:
            st.session_state['pci_vm_list'] = []
        if 'pci_selected_vm' not in st.session_state:
            st.session_state['pci_selected_vm'] = None
        if 'pci_log' not in st.session_state:
            st.session_state['pci_log'] = []
        def pci_reset_button():
            if st.button("Reset/Restart"):
                for k in ['pci_step','pci_form_data','pci_si','pci_vm_list','pci_selected_vm','pci_log']:
                    if k in st.session_state:
                        del st.session_state[k]
            st.rerun()

        from main_MTY import PciPassthruConfigurator
        c = PciPassthruConfigurator()

        form_col, _ = st.columns([2, 1])
        with form_col:
            if st.session_state['pci_step'] == 0:
                with st.form("pci_host_form"):
                    esxi_host = st.text_input("ESXi Host IP address")
                    esxi_password = st.text_input("ESXi password", type="password", value="Passw0rd!")
                    submitted = st.form_submit_button("Next: Connect & List VMs", type="primary")
                if submitted:
                    if not esxi_host or not esxi_password:
                        st.error("❌ Please fill in all required fields.")
                        st.stop()
                    if not c.validate_ip(esxi_host):
                        st.error("❌ Invalid IP format.")
                        st.stop()
                    connected, si = c.test_connection(esxi_host, c.user, esxi_password)
                    if not connected:
                        st.error("❌ Failed to connect to ESXi host. Please check credentials and network.")
                        pci_reset_button()
                        st.stop()
                    vm_list = c.list_vms(si)
                    if not vm_list:
                        st.error("❌ No VMs found on ESXi host.")
                        pci_reset_button()
                        st.stop()
                    st.session_state['pci_form_data'] = {
                        'esxi_host': esxi_host,
                        'esxi_password': esxi_password
                    }
                    st.session_state['pci_si'] = si
                    st.session_state['pci_vm_list'] = vm_list
                    st.session_state['pci_step'] = 1
                    st.rerun()
            elif st.session_state['pci_step'] == 1:
                st.success("✅ Connected to ESXi host successfully.")
                vm_list = st.session_state['pci_vm_list']
                selected_vm = st.selectbox("Select VM to enable PCI passthrough:", options=vm_list)
                if st.button("Next: Review & Enable", type="primary"):
                    st.session_state['pci_selected_vm'] = selected_vm
                    st.session_state['pci_step'] = 2
                    st.rerun()
                pci_reset_button()
            elif st.session_state['pci_step'] == 2:
                data = st.session_state['pci_form_data']
                selected_vm_name = st.session_state['pci_selected_vm']
                si = st.session_state['pci_si']
                st.subheader("Summary")
                st.json({
                    "ESXi Host": data['esxi_host'],
                    "VM to enable PCI passthrough": selected_vm_name
                })
                try:
                    content = si.RetrieveContent()
                    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                    vm_to_check = next((v for v in list(container.view) if v.name == selected_vm_name), None)
                    container.Destroy()
                    if not vm_to_check:
                        st.error(f"Could not find VM '{selected_vm_name}'.")
                    elif vm_to_check.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                        st.error(f"VM '{selected_vm_name}' is currently powered on. Please power it off before enabling PCI passthrough.", icon="🚨")
                    else:
                        st.warning("This operation will attempt to enable PCI passthrough for all NVIDIA GPUs on the host and attach them to the selected VM.", icon="⚠️")
                        if st.button("Confirm and Enable PCI passthrough", type="primary"):
                            st.session_state['pci_step'] = 3
                            st.rerun()
                except Exception as e:
                    st.error(f"Could not check VM power state: {e}")
                pci_reset_button()
            elif st.session_state['pci_step'] == 3:
                si = st.session_state['pci_si']
                selected_vm = st.session_state['pci_selected_vm']
                st.info(f"Enabling PCI passthrough for NVIDIA GPUs and attaching to VM '{selected_vm}'...")
                log_box = st.empty()
                log_lines = []
                try:
                    # 直接複製 main_MTY.py 的 add_vm_options 主要邏輯
                    content = si.RetrieveContent()
                    vm = None
                    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
                    for managed_object in container.view:
                        if managed_object.name == selected_vm:
                            vm = managed_object
                            break
                    container.Destroy()
                    if not vm:
                        st.error(f"VM name: '{selected_vm}' is not found")
                        pci_reset_button()
                        st.stop()
                    host = vm.runtime.host
                    nvidia_devices = []
                    for pci_dev in host.hardware.pciDevice:
                        if "NVIDIA" in pci_dev.vendorName:
                            nvidia_devices.append(pci_dev)
                            log_lines.append(f"Found NVIDIA PCI device: {pci_dev.deviceName} ({pci_dev.id})")
                    if not nvidia_devices:
                        st.error("No NVIDIA PCI device found on the host.")
                        pci_reset_button()
                        st.stop()
                    log_box.code('\n'.join(log_lines), language="log")
                    passthru_sys = host.configManager.pciPassthruSystem
                    if passthru_sys:
                        configs = []
                        for dev in nvidia_devices:
                            config = vim.host.PciPassthruConfig()
                            config.id = dev.id
                            config.passthruEnabled = True
                            configs.append(config)
                        try:
                            passthru_sys.UpdatePassthruConfig(configs)
                            log_lines.append("Successfully updated PCI passthrough configuration for all NVIDIA devices.")
                        except Exception as e:
                            st.error(f"Failed to update PCI passthrough config: {e}")
                            pci_reset_button()
                            st.stop()
                        device_changes = []
                        for dev in nvidia_devices:
                            pci_spec = vim.vm.device.VirtualDeviceSpec()
                            pci_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
                            pci_device = vim.vm.device.VirtualPCIPassthrough()
                            pci_device.backing = vim.vm.device.VirtualPCIPassthrough.DeviceBackingInfo()
                            pci_device.backing.id = dev.id
                            pci_device.backing.deviceId = hex(dev.deviceId)[2:].zfill(4)
                            pci_device.backing.systemId = host.hardware.systemInfo.uuid
                            pci_device.backing.vendorId = dev.vendorId
                            pci_device.key = -1
                            pci_spec.device = pci_device
                            device_changes.append(pci_spec)
                        vm_config_spec = vim.vm.ConfigSpec()
                        vm_config_spec.deviceChange = device_changes
                        log_lines.append(f"Attempting to add {len(nvidia_devices)} PCI device(s) to VM '{selected_vm}'...")
                        log_box.code('\n'.join(log_lines), language="log")
                        task = vm.ReconfigVM_Task(spec=vm_config_spec)
                        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                            time.sleep(1)
                        if task.info.state == vim.TaskInfo.State.success:
                            log_lines.append(f"Successfully added PCI passthrough device(s) to '{selected_vm}'")
                            mmio_size = '2048' if len(nvidia_devices) > 1 else '256'
                            try:
                                vm_config_spec = vim.vm.ConfigSpec()
                                extra_config = [
                                    vim.option.OptionValue(key='pciHole.start', value='2048'),
                                    vim.option.OptionValue(key='pciPassthru.use64bitMMIO', value='TRUE'),
                                    vim.option.OptionValue(key='pciPassthru.64bitMMIOSizeGB', value=mmio_size)
                                ]
                                if len(nvidia_devices) > 1:
                                    extra_config.append(vim.option.OptionValue(key='pciPassthru.allowP2P', value='TRUE'))
                                vm_config_spec.extraConfig = extra_config
                                vm_config_spec.memoryReservationLockedToMax = True
                                log_lines.append(f"Adding VM options to '{selected_vm}'...")
                                log_box.code('\n'.join(log_lines), language="log")
                                task = vm.ReconfigVM_Task(spec=vm_config_spec)
                                while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                                    time.sleep(1)
                                if task.info.state == vim.TaskInfo.State.success:
                                    log_lines.append(f"Successfully added VM options to '{selected_vm}'")
                                else:
                                    log_lines.append(f"Failed to add VM options: {task.info.error}")
                            except Exception as e:
                                log_lines.append(f"Error adding VM options: {e}")
                        else:
                            log_lines.append(f"Failed to add PCI passthrough device(s) to VM: {task.info.error}")
                        log_box.code('\n'.join(log_lines), language="log")
                        # 完成後切換到 step 4
                        st.session_state['pci_step'] = 4
                        st.rerun()
                except Exception as e:
                    st.error(f"An error occurred: {e}")
                    st.session_state['pci_step'] = 4
                    st.rerun()
            elif st.session_state['pci_step'] == 4:
                st.success("🎉 PCI passthrough for NVIDIA GPU completed!")
                if st.button("Reset/Restart"):
                    for k in ['pci_step','pci_form_data','pci_si','pci_vm_list','pci_selected_vm','pci_log']:
                        if k in st.session_state:
                            del st.session_state[k]
                    st.rerun()
                st.stop()
    elif choice == "Copy Agent execution log":
        st.header(":blue[Copy Agent execution log]")
        st.info("""
        **Prerequisites**
        - Agent is deployed and running on TC
        - You have the Agent's IP address
        """, icon="ℹ️")

        # Session state keys
        LOG_RESET_KEYS = [
            'log_step', 'log_form_data', 'log_ssh', 'log_first_level', 'log_second_level',
            'log_test_cases', 'log_selected_test_case', 'log_fourth_level', 'log_remote_path',
            'log_local_path', 'log_copy_success', 'log_error_msg', 'log_local_dir'
        ]
        def log_reset_button():
            if st.button("Reset/Restart"):
                for k in LOG_RESET_KEYS:
                    if k in st.session_state:
                        del st.session_state[k]
                st.rerun()

        # Initialize step
        if 'log_step' not in st.session_state:
            st.session_state['log_step'] = 0

        c = ResultLogCopier()

        if st.session_state['log_step'] == 0:
            form_col, _ = st.columns([2, 1])
            with form_col:
                with st.form("log_connect_form"):
                    agent_ip = st.text_input("Agent IP address")
                    submitted = st.form_submit_button("Connect", type="primary")
            if submitted:
                if not c.validate_ip(agent_ip):
                    st.error("❌ Invalid IP format.")
                    st.stop()
                with st.spinner("Connecting to Agent via SSH..."):
                    ssh = c.ssh_connect(agent_ip, c.username, c.password)
                    if not ssh:
                        st.error("❌ SSH connection failed. Please check IP/SSH status.")
                        st.stop()
                st.session_state['log_ssh'] = ssh
                st.session_state['log_form_data'] = {'agent_ip': agent_ip}
                st.session_state['log_step'] = 1
                st.rerun()

        elif st.session_state['log_step'] == 1:
            ssh = st.session_state['log_ssh']
            def get_test_cases_via_ssh(ssh, path):
                cmd = (
                    f"for d in {path}/*/; do "
                    "t=$(find \"$d\" -type f -printf '%T@\\n' 2>/dev/null | sort -n | tail -1); "
                    "if [ -n \"$t\" ]; then echo \"$t $d\"; fi; "
                    "done | sort -n"
                )
                stdin, stdout, stderr = ssh.exec_command(cmd)
                lines = stdout.read().decode().strip().split('\n')
                dirs = []
                for line in lines:
                    if line.strip():
                        parts = line.strip().split(' ', 1)
                        if len(parts) == 2:
                            dir_path = parts[1].rstrip('/')
                            dirs.append(os.path.basename(dir_path))
                return dirs

            with st.spinner("Getting latest result directory..."):
                first_level = c.get_latest_directory(ssh, "/results")
                if not first_level:
                    st.error("No result directories found on Agent.")
                    log_reset_button()
                    st.stop()
                second_level = c.get_latest_directory(ssh, f"/results/{first_level}")
                if not second_level:
                    st.error("No second level directories found.")
                    log_reset_button()
                    st.stop()
                test_cases = get_test_cases_via_ssh(ssh, f"/results/{first_level}/{second_level}")
                if not test_cases:
                    st.error("No test cases found.")
                    log_reset_button()
                    st.stop()
            st.info(f"**Current latest result directories:**\n- First level: `{first_level}`\n- Second level: `{second_level}`", icon="📁")
            selected_test_case = st.radio("Select test case to copy log from:", options=test_cases, index=0)
            import os
            default_log_dir = os.getcwd()
            log_dir_raw = st.text_input("Local directory to save run.log", value=default_log_dir)
            log_dir = log_dir_raw.strip().strip('"').strip("'")
            if log_dir and not os.path.isdir(log_dir):
                st.warning("⚠️ This directory does not exist. Please check the path.")
                st.stop()
            if st.button("Next: Prepare to Copy", type="primary"):
                st.session_state['log_first_level'] = first_level
                st.session_state['log_second_level'] = second_level
                st.session_state['log_test_cases'] = test_cases
                st.session_state['log_selected_test_case'] = selected_test_case
                st.session_state['log_local_dir'] = log_dir
                st.session_state['log_step'] = 2
                st.rerun()

        elif st.session_state['log_step'] == 2:
            test_case = st.session_state['log_selected_test_case']
            log_dir = st.session_state['log_local_dir']
            ssh = st.session_state['log_ssh']
            first_level = st.session_state['log_first_level']
            second_level = st.session_state['log_second_level']
            with st.spinner("Getting latest run log directory..."):
                fourth_level = c.get_latest_directory(ssh, f"/results/{first_level}/{second_level}/{test_case}")
                if not fourth_level:
                    st.error("No run logs found for this test case.")
                    log_reset_button()
                    st.stop()
                remote_path = f"/results/{first_level}/{second_level}/{test_case}/{fourth_level}/run.log"
                stdin, stdout, stderr = ssh.exec_command(f"test -f {remote_path} && echo 'exists'")
                if not stdout.read().decode().strip():
                    st.error(f"run.log not found at {remote_path}")
                    log_reset_button()
                    st.stop()
                safe_test_case = c.sanitize_filename(test_case)
                safe_fourth_level = c.sanitize_filename(fourth_level)
                import os
                local_dir = os.path.join(log_dir, safe_test_case, safe_fourth_level)
                try:
                    os.makedirs(local_dir, exist_ok=True)
                except OSError as e:
                    st.error(f"❌ Failed to create directory: {local_dir}\nError: {e}\nPlease check your path and try again.")
                    log_reset_button()
                    st.stop()
                local_path = os.path.join(local_dir, "run.log")
            st.session_state['log_fourth_level'] = fourth_level
            st.session_state['log_remote_path'] = remote_path
            st.session_state['log_local_path'] = local_path
            st.session_state['log_step'] = 4 # 直接跳到步驟 4 準備複製
            st.rerun()

        elif st.session_state['log_step'] == 4:
            remote_path = st.session_state['log_remote_path']
            local_path = st.session_state['log_local_path']
            st.info(f"**Ready to copy log file:**\n- Remote: `{remote_path}`\n- Local: `{local_path}`")
            if st.button("Copy run.log", type="primary"):
                ssh = st.session_state['log_ssh']
                with st.spinner("Copying run.log to local machine..."):
                    success = c.copy_run_log(ssh, remote_path, local_path)
                    if success:
                        st.session_state['log_copy_success'] = True
                        st.session_state['log_step'] = 5
                        st.rerun()
                    else:
                        st.session_state['log_error_msg'] = "Failed to copy run.log."
                        st.session_state['log_copy_success'] = False
                        st.session_state['log_step'] = 5
                        st.rerun()
            log_reset_button()

        elif st.session_state['log_step'] == 5:
            if st.session_state.get('log_copy_success'):
                st.success("Successfully copied run.log!")
                st.code(st.session_state['log_local_path'], language='text')
            else:
                st.error(st.session_state.get('log_error_msg', 'Failed to copy run.log.'))
            if st.button("Copy another test case"):
                for k in ['log_step','log_selected_test_case','log_fourth_level','log_remote_path','log_local_path','log_copy_success','log_error_msg','log_local_dir']:
                    if k in st.session_state:
                        del st.session_state[k]
                st.session_state['log_step'] = 1
                st.rerun()
            log_reset_button()
