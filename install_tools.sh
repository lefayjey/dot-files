#!/bin/bash -e
# Author: lefayjey
# last updated: 24/02/2026

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

low_priv_user="kali"
tools_dir="/opt/Tools"

windows_tools="${tools_dir}/windows"
linux_tools="${tools_dir}/linux"
mobile_tools="${tools_dir}/mobile"
other_tools="${tools_dir}/other"
cloud_tools="${tools_dir}/cloud"

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo or as root"
    exit 1
fi

get_latest_releases() {
    urls=$(curl -s "$1/releases/latest" | grep "tag" | cut -d "\"" -f 2)
    for u in $urls; do
        files=$(curl -s "$u" | grep "releases/download" | cut -d "\"" -f 2)
        for f in $files; do
            wget -q -N "https://github.com/$f" -P "$2/"
        done
    done
}

system_update() {
    echo -e "\n${BLUE}[Initiate]${NC} System update\n"
    apt update && apt upgrade -y
    echo -e "\n${GREEN}[Success]${NC} System update\n"
}

install_software() {
    echo -e "\n${BLUE}[Initiate]${NC} Install additional software\n"

    apt install -y cloc sloccount renameutils html2text npm golang \
        ranger feh scrot jsbeautifier blueman ideviceinstaller neovim \
        parallel mono-devel default-jdk redis-server freetds-bin freetds-common freetds-dev \
        network-manager-openvpn network-manager-ssh network-manager-openconnect \
        libcurl4-openssl-dev libpcre3-dev libssh-dev \
        jxplorer veil shellter powercat dnscat2 snmp snmp-mibs-downloader

    python3 -m pip install --upgrade pip
    pip3 install --user pipx PyYAML alive-progress xlsxwriter sectools pwn dsinternals --upgrade
    pipx ensurepath

    # Scan/exploit
    pipx install pwncat-cs --force
    pipx install wesng --force

    # AD/Windows
    pipx install pypykatz --force
    pipx install autobloody --force
    pipx install minikerberos --force
    pipx install "git+https://github.com/c3c/ADExplorerSnapshot.py.git" --force

    # Mobile
    pipx install frida-tools --force
    pipx install objection --force

    # Cloud
    pipx install pacu --force
    pipx install principalmapper --force
    pipx install roadrecon --force
    pipx install scoutsuite --force
    pipx install prowler --force

    # linWinPwn tooling
    pipx install git+https://github.com/dirkjanm/ldapdomaindump.git --force
    pipx install git+https://github.com/Pennyw0rth/NetExec.git --force
    pipx install git+https://github.com/fortra/impacket.git --force
    pipx install git+https://github.com/dirkjanm/adidnsdump.git --force
    pipx install git+https://github.com/zer1t0/certi.git --force
    pipx install git+https://github.com/ly4k/Certipy.git --force
    pipx install git+https://github.com/dirkjanm/bloodhound.py --force
    pipx install "git+https://github.com/dirkjanm/BloodHound.py@bloodhound-ce" --force --suffix '_ce'
    pipx install git+https://github.com/franc-pentest/ldeep.git --force
    pipx install git+https://github.com/garrettfoster13/pre2k.git --force
    pipx install git+https://github.com/zblurx/certsync.git --force
    pipx install hekatomb --force
    pipx install git+https://github.com/blacklanternsecurity/MANSPIDER --force
    pipx install git+https://github.com/p0dalirius/Coercer --force
    pipx install git+https://github.com/CravateRouge/bloodyAD --force
    pipx install git+https://github.com/login-securite/DonPAPI --force
    pipx install git+https://github.com/p0dalirius/RDWAtool --force
    pipx install git+https://github.com/almandin/krbjack --force
    pipx install git+https://github.com/CompassSecurity/mssqlrelay.git --force
    pipx install git+https://github.com/oppsec/breads.git --force
    pipx install git+https://github.com/p0dalirius/smbclient-ng --force

    # GEF for GDB
    bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

    echo -e "\n${GREEN}[Success]${NC} Install additional software\n"
}

wget_tools() {
    mkdir -p "${windows_tools}" "${other_tools}" "${mobile_tools}" "${cloud_tools}"

    #-------------------------------------------------------Windows----------------------------------------------------------
    echo -e "${GREEN}Getting Windows tools:${NC}"

    # Windows Misc Utilities
    echo -e "\tSysInternalsSuite"
    wget -q "https://download.sysinternals.com/files/SysinternalsSuite.zip" -O "${windows_tools}/SysinternalsSuite.zip"
    echo -e "\tAPI Monitor"
    wget -q "http://www.rohitab.com/download/api-monitor-v2r13-x86-x64.zip" -O "${windows_tools}/api-monitor-v2r13-x86-x64.zip"
    echo -e "\tNetscan"
    wget -q "https://www.softperfect.com/download/files/netscan_portable.zip" -O "${windows_tools}/netscan_portable.zip"
    echo -e "\tSMBEagle"
    wget -q "https://github.com/punk-security/smbeagle/releases/download/4.0.1/smbeagle_4.0.1_linux_amd64.zip" -O "${windows_tools}/smbeagle_4.0.1_linux_amd64.zip"
    wget -q "https://github.com/punk-security/smbeagle/releases/download/4.0.1/smbeagle_4.0.1_win_x64.zip" -O "${windows_tools}/smbeagle_4.0.1_win_x64.zip"

    # C2
    echo -e "\tEmpire"
    wget -q "https://github.com/BC-SECURITY/Empire/archive/master.zip" -O "${windows_tools}/Empire.zip"
    echo -e "\tStarKiller"
    get_latest_releases "https://github.com/BC-SECURITY/Starkiller" "${windows_tools}"
    echo -e "\tOffensivePipeline"
    get_latest_releases "https://github.com/Aetsu/OffensivePipeline" "${windows_tools}"

    # Credentials collection
    echo -e "\tNirsoft Tools"
    wget -q "https://download.nirsoft.net/nirsoft_package_enc_1.30.3.zip" -O "${windows_tools}/nirsoft_package_enc_1.30.3.zip"

    # Evasion and bypass
    echo -e "\tPowerShdll"
    get_latest_releases "https://github.com/p3nt4/PowerShdll" "${windows_tools}"

    # PowerShell and Sharp Collections
    echo -e "\tPowerSploit"
    wget -q "https://github.com/PowerShellMafia/PowerSploit/archive/master.zip" -O "${windows_tools}/PowerSploit.zip"
    echo -e "\tSharpSploit"
    wget -q "https://github.com/cobbr/SharpSploit/archive/master.zip" -O "${windows_tools}/SharpSploit.zip"
    echo -e "\tNishang"
    wget -q "https://github.com/samratashok/nishang/archive/master.zip" -O "${windows_tools}/nishang.zip"
    echo -e "\toleviewdotnet"
    get_latest_releases "https://github.com/tyranid/oleviewdotnet" "${windows_tools}"

    #----------------------------------------------------------AD------------------------------------------------------------
    echo -e "${GREEN}Getting AD tools:${NC}"

    echo -e "\tADModule"
    wget -q "https://github.com/samratashok/ADModule/archive/master.zip" -O "${windows_tools}/ADModule.zip"
    echo -e "\tANSSI AD Control Paths"
    get_latest_releases "https://github.com/ANSSI-FR/AD-control-paths" "${windows_tools}"
    echo -e "\tPingCastle"
    get_latest_releases "https://github.com/vletoux/pingcastle" "${windows_tools}"
    echo -e "\tThycoticWeakPasswordFinder"
    wget -q "https://d36zgw9sidnotm.cloudfront.net/FreeTools/ThycoticWeakPasswordFinder.zip" -O "${windows_tools}/ThycoticWeakPasswordFinder.zip"
    echo -e "\tgo-windapsearch"
    get_latest_releases "https://github.com/ropnop/go-windapsearch" "${windows_tools}"
    echo -e "\tadmpwd"
    get_latest_releases "https://github.com/GreyCorbel/admpwd" "${windows_tools}"

    #------------------------------------------------Mobile-------------------------------------------------------
    echo -e "${GREEN}Getting Mobile tools:${NC}"
    echo -e "\tMobSF"
    wget -q "https://github.com/MobSF/Mobile-Security-Framework-MobSF/archive/master.zip" -O "${mobile_tools}/Mobile-Security-Framework-MobSF.zip"

    #------------------------------------------------Cloud-------------------------------------------------------
    echo -e "${GREEN}Getting Cloud tools:${NC}"
    echo -e "\tScubaGear"
    wget -q "https://github.com/cisagov/ScubaGear/archive/master.zip" -O "${cloud_tools}/ScubaGear.zip"

    #------------------------------------------------Other-------------------------------------------------------
    echo -e "${GREEN}Getting Other tools:${NC}"
    echo -e "\tChisel"
    get_latest_releases "https://github.com/jpillora/chisel" "${other_tools}"
    echo -e "\tpcileech"
    get_latest_releases "https://github.com/ufrisk/pcileech" "${other_tools}"
    echo -e "\taquatone"
    get_latest_releases "https://github.com/michenriksen/aquatone" "${other_tools}"
    echo -e "\tdnscat"
    wget -q "https://downloads.skullsecurity.org/dnscat2/dnscat2-v0.07-client-x64.tar.bz2" -O "${other_tools}/dnscat2-v0.07-client-x64.tar.bz2"
    wget -q "https://downloads.skullsecurity.org/dnscat2/dnscat2-v0.07-client-win32.zip" -O "${other_tools}/dnscat2-v0.07-client-win32.zip"
    echo -e "\tysoserial"
    wget -q "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" -O "${other_tools}/ysoserial-all.jar"
    get_latest_releases "https://github.com/pwntester/ysoserial.net" "${other_tools}"

    chown "$low_priv_user:$low_priv_user" -R "$tools_dir"
}

#### Calling functions
system_update    || { echo -e "\n\n${RED}[Failure]${NC} System update failed.. exiting script!\n"; exit 1; }
install_software || { echo -e "\n\n${RED}[Failure]${NC} Software install failed.. exiting script!\n"; exit 1; }
wget_tools       || { echo -e "\n\n${RED}[Failure]${NC} Download tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} finished!\n"