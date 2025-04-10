#!/usr/bin/env bash


# CREATOR: Mike Lu (klu7@lenovo.com)
# CHANGE DATE: 3/27/2025
__version__="1.0"


# Quick Setup For VMWare GPU DPIO (Direct Path I/O) Cert Testing - VIVa


# User-defined settings
Gateway="192.168.4.7"
DNS="10.241.96.14"


# Color settings
red='\e[41m'
green='\e[32m'
yellow='\e[93m'
nc='\e[0m'


# Check Internet connection
CheckInternet() {
    nslookup "google.com" > /dev/null
    if [ $? != 0 ]; then 
        echo -e "${red}No Internet connection! Please check your network${nc}" && sleep 5 && exit 1
    fi
}


# Ensure the user is running the script as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${yellow️}Please login as root to run this script${nc}"
    exit 1
fi
    

echo "╭─────────────────────────────────────────────────╮"
echo "│   VMware Certification Test Environment Setup   │"
echo "│                 VIVa Config                     │"
echo "╰─────────────────────────────────────────────────╯"
# Install sshpass on jump server 
echo
echo "--------------------------------"
echo "INSATL SSHPASS ON JUMP SERVER..."
echo "--------------------------------"
echo
if [[ -f /usr/bin/apt ]]; then
    PKG=apt
elif [[ -f /usr/bin/dnf ]]; then
    PKG=dnf
fi
case $PKG in
    "apt")
        if ! command -v sshpass > /dev/null 2>&1; then
            CheckInternet
            sudo apt update && sudo apt install sshpass -y ||  { echo -e "\n❌ Failed to install sshpass"; exit 1; }
        fi
        ;;
    "dnf")
        if ! command -v sshpass > /dev/null 2>&1; then
            CheckInternet
            sudo dnf install sshpass -y ||  { echo -e "\n❌ Failed to install sshpass"; exit 1; }
        fi
        ;;
esac 
echo -e "\n${green}Done!${nc}\n" 


# Validate and configure VIVa internal IP
configure_internal_ip() {
    echo -e "\n---------------------"
    echo "CONFIG INTERNAL IP..."
    echo "---------------------\n"

    # Input and validate internal IP
    while true; do
        read -p "Enter VIVa local IP (DHCP): " VIVA_IP_internal
        if [[ "$VIVA_IP_internal" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        else
            echo -e "${yellow}Invalid format${nc}"
        fi
    done

    # Ping check
    if ! timeout 5 ping -c 3 "$VIVA_IP_internal" > /dev/null 2>&1; then
        echo -e "${red}Ping to $VIVA_IP_internal failed. Please check the IP address and network connection.${nc}"
        exit 1
    fi

    # SSH key management
    SSH_KEY_PATH="$HOME/.ssh/id_rsa_viva_$VIVA_IP_internal"
    if [ ! -f "$SSH_KEY_PATH" ]; then
        ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_PATH" -N ""
    fi

    # SSH and configure internal IP
    sshpass -p "vmware" ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" "root@$VIVA_IP_internal" "
        echo 'vmware' | sudo -S true
        grep -q '$VIVA_IP_internal cert-viva-local' /etc/hosts ||  
            sudo sed -i '/# End/i $VIVA_IP_internal cert-viva-local' /etc/hosts
    "

    [[ $? = 0 ]] && echo -e "\n${green}Internal IP configuration done!${nc}\n" || { echo -e "${red}Failed to configure internal IP on VIVa${nc}"; exit 1; }
    echo "$VIVA_IP_internal"
}


# Configure external network
configure_external_network() {
    local VIVA_IP_internal="$1"
    
    echo -e "\n------------------------"
    echo "CONFIG EXTERNAL NETWORK "
    echo "------------------------\n"

    # Input and validate external IP
    while true; do
        read -p "Assign VIVa external IP (Internet): " VIVA_IP_external
        if [[ "$VIVA_IP_external" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        else
            echo -e "${yellow}Invalid format${nc}"
        fi
    done

    # SSH and configure external network
    sshpass -p "vmware" ssh -o StrictHostKeyChecking=no -i "$HOME/.ssh/id_rsa_viva_$VIVA_IP_internal" "root@$VIVA_IP_internal" "
        echo 'vmware' | sudo -S true
        
        # Network configuration file
        CONFIG_FILE='/etc/systemd/network/99-dhcp-en.network'
        
        # Disable DHCP
        sudo sed -i 's/DHCP=yes/DHCP=no/' '$CONFIG_FILE'
        
        # Add static IP address
        grep -q 'Address=$VIVA_IP_external/22' '$CONFIG_FILE' || 
            sudo sed -i '/DHCP=no/a Address=$VIVA_IP_external/22' '$CONFIG_FILE'
        
        # Add Gateway
        grep -q 'Gateway=$Gateway' '$CONFIG_FILE' || 
            sudo sed -i '/Address=$VIVA_IP_external\/22/a Gateway=$Gateway' '$CONFIG_FILE'
        
        # Add DNS
        grep -q 'DNS=$DNS' '$CONFIG_FILE' || 
            sudo sed -i '/Gateway=$Gateway/a DNS=$DNS' '$CONFIG_FILE'
        
        # Apply network settings
        sudo systemctl restart systemd-networkd
        
        # Check internet
        nslookup google.com > /dev/null 2>&1
    "

    [[ $? = 0 ]] && echo -e "\n${green}External network configuration done!${nc}\n" || { echo -e "${red}Failed to configure external network on VIVa${nc}"; exit 1; }
}

# Main script execution
VIVA_IP_internal=$(configure_internal_ip)
configure_external_network "$VIVA_IP_internal"



    
    
exit