#!/bin/bash -e
# Authors: JOF
# last updated: 31/07/2021

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

low_priv_user="kali"
tools_dir="/opt/Tools/"

windows_tools="${tools_dir}/windows"
linux_tools="${tools_dir}/linux"
mobile_tools="${tools_dir}/mobile"
other_tools="${tools_dir}/other"
cloud_tools="${tools_dir}/cloud"

if [ "$EUID" -ne 0 ]
    then echo "Please run with sudo or as root "
    exit
fi

get_latest_releases () {
	urls=$(curl -s $1/releases/latest | grep "tag" | cut -d "\"" -f 2);
	for u in $urls; do
		files=$(curl -s $u | grep "releases/download"| cut -d "\"" -f 2);
		for f in $files; do
			wget -q -N "https://github.com/"$f -P $2/;
		done;
	done;
}

# Function definitions
system_update(){
    echo -e "\n${BLUE}[Initiate]${NC} System update\n"
    apt update && apt upgrade -y
    echo -e "\n${GREEN}[Success]${NC} System update\n"
}

install_ftp() {
    echo -e "\n${BLUE}[Initiate]${NC} Installing FTP\n"
	apt install pure-ftpd
	pure-pw useradd $low_priv_user -u $low_priv_user -d /home/$low_priv_user/ftp
	pure-pw mkdb
	ln -s /etc/pure-ftpd/auth/conf/PureDB 60pdb
	mkdir -p /home/$low_priv_user/ftp
	chown -R $low_priv_user:$low_priv_user /home/$low_priv_user/ftp
	/etc/init.d/pure-ftpd restart
	echo -e "\n${GREEN}[Success]${NC} Installing FTP\n"
}

install_smb() {
    echo -e "\n${BLUE}[Initiate]${NC} Installing SMB\n"
	apt install samba
	mv /etc/samba/smb.conf /etc/samba/smb.conf.old
	echo "[share]" >> /etc/samba/smb.conf
	echo "path = /home/$low_priv_user/smb" >> /etc/samba/smb.conf
	echo "browseable = yes" >> /etc/samba/smb.conf
	echo "read only = no" >> /etc/samba/smb.conf
	smbpasswd -a $low_priv_user
	systemctl start smbd
	systemctl start nmbd
	mkdir -p /home/$low_priv_user/smb
	chmod -R $low_priv_user:$low_priv_user /home/$low_priv_user/smb
	echo -e "\n${GREEN}[Success]${NC} Installing SMB\n"
}

create_aliases() {
    
	##prepare VM mounting script
	cat <<EOF >/usr/local/sbin/vm-mount
#!/bin/bash
setxkbmap ch
cp /usr/share/zoneinfo/Europe/Zurich /etc/localtime
w > /dev/null
date

systemctl stop run-vmblock-fuse.mount 2>/dev/null
killall -q -w vmtoolsd 2>/dev/null
systemctl start run-vmblock-fuse.mount 2>/dev/null
systemctl enable run-vmblock-fuse.mount 2>/dev/null
vmware-user-suid-wrapper vmtoolsd -n vmusr 2>/dev/null
vmtoolsd -b /var/run/vmroot 2>/dev/null

vmware-hgfsclient | while read folder; do
vmwpath="/mnt/hgfs/\${folder}"
echo "[i] Mounting \${folder}   (\${vmwpath})"
sudo mkdir -p "\${vmwpath}"
sudo umount -f "\${vmwpath}" 2>/dev/null
sudo vmhgfs-fuse -o allow_other -o auto_unmount ".host:/\${folder}" "\${vmwpath}"
done
sleep 2s

for i in /mnt/hgfs/\$(vmware-hgfsclient)/*/; do
	ln -s \$i /opt 2>/dev/null;
done
EOF
	chmod +x /usr/local/sbin/vm-mount

	cat <<EOF >/usr/local/sbin/bloodhound-start
#!/bin/bash
NEOSTATUS=\$(sudo neo4j status)
if [ "\$NEOSTATUS" == "Neo4j is not running" ]; then
   echo "Database is not running. Starting..."
   sudo neo4j start
   sleep 10
   bloodhound --no-sandbox
else
   echo "Database is already started."
   bloodhound --no-sandbox
fi
EOF
	chmod +x /usr/local/sbin/bloodhound-start

	##adding aliases to zshrc
    echo -e "\n${BLUE}[Initiate]${NC} aliases \n"
    echo -e "## $low_priv_user's aliases" >> /home/$low_priv_user/.zshrc
    echo 'alias impacket="/usr/share/doc/python3-impacket/examples"' >> /home/$low_priv_user/.zshrc
    echo 'alias www="python3 -m http.server 8000 --directory /opt/PentestTools/"' >> /home/$low_priv_user/.zshrc
    echo 'alias smb="python3 /usr/local/bin/smbserver.py TOOLS /opt/PentestTools/ -smb2 -username username -password password"' >> /home/$low_priv_user/.zshrc
    echo 'alias htb="openvpn /opt/CTF/hackthebox/cerebro11.ovpn"' >> /home/$low_priv_user/.zshrc
    echo 'alias thm="openvpn /opt/CTF/tryhackme/cerebro11.ovpn"' >> /home/$low_priv_user/.zshrc
	echo 'alias vpnip="/sbin/ifconfig tun0 | grep "inet " | cut -d " " -f 10"' >> /home/$low_priv_user/.zshrc
	echo 'alias serv="sudo service apache2 start; sudo service smbd start; sudo service nmbd start; sudo service pure-ftpd start; sudo service ssh start"' >> /home/$low_priv_user/.zshrc

    echo -e "## root's aliases" >> /root/.zshrc
    echo 'alias impacket="/usr/share/doc/python3-impacket/examples"' >> /root/.zshrc
    echo 'alias www="python3 -m http.server 8000 --directory /opt/PentestTools/"; echo "IP: http://$(vpnip):8000\nDirectory: /opt/PentestTools/"' >> /root/.zshrc
    echo 'alias smb="python3 /usr/share/doc/python3-impacket/examples/smbserver.py TOOLS /opt/PentestTools/ -smb2 -username username -password password"' >> /root/.zshrc
    echo 'alias htb="openvpn /opt/CTF/hackthebox/cerebro11.ovpn"' >> /root/.zshrc
    echo 'alias thm="openvpn /opt/CTF/tryhackme/cerebro11.ovpn"' >> /root/.zshrc
	echo 'alias vpnip="/sbin/ifconfig tun0 | grep "inet " | cut -d " " -f 10"' >> /root/.zshrc
	echo 'alias serv="sudo service apache2 start; sudo service smbd start; sudo service nmbd start; sudo service pure-ftpd start; sudo service ssh start"' >> /root/.zshrc

    echo -e "\n${GREEN}[Success]${NC} aliases \n"
}

copy_i3_config_files() {
    #copy i3 configfiles
    echo -e "\n${BLUE}[Initiate]${NC} copying i3 config files\n"
    conf=i3blocks.conf
    dotfile_dir="./dot-files"

    mkdir -p /root/.config/i3/
    cp $dotfile_dir/i3/config /root/.config/i3/
	dos2unix /root/.config/i3/config
    cp $dotfile_dir/i3/$conf /root/.config/i3/i3blocks.conf
	dos2unix /root/.config/i3/i3blocks.conf
    chown -R root /root/.config/i3/
    cp $dotfile_dir/scripts/lock_screen.sh /usr/bin/lock_screen.sh
    mkdir -p /home/$low_priv_user/.config/i3/
    cp $dotfile_dir/i3/config /home/$low_priv_user/.config/i3/
    dos2unix /home/$low_priv_user/.config/i3/config
	cp $dotfile_dir/i3/$conf /home/$low_priv_user/.config/i3/i3blocks.conf
	dos2unix /home/$low_priv_user/.config/i3/i3blocks.conf
    chown -R $low_priv_user /home/$low_priv_user/.config/i3/
    chown -R $low_priv_user /usr/bin/lock_screen.sh
    echo -e "\n${GREEN}[Success]${NC} copying i3 config files \n"
}

install_shitload_software() {
    echo -e "\n${BLUE}[Initiate]${NC} Install shitload of software \n"
    
    #dpkg --add-architecture i386

    apt install dos2unix python3 python3-dev python3-pip python3-venv eog cloc sloccount nfs-common \
        renameutils sshfs jxplorer pdfgrep html2text xclip npm git tigervnc-viewer xcwd \
        i3blocks i3lock rofi dmenu htop tmux cifs-utils ranger feh scrot jsbeautifier krb5-user \
        lightdm lightdm-remote-session-freerdp2 flameshot blueman ideviceinstaller golang neovim \
        jadx filezilla parallel rlwrap 2to3 mono-devel default-jdk graphicsmagick-imagemagick-compat \
        redis-server network-manager-openvpn sqsh freetds-bin freetds-common freetds-dev \
        network-manager-ssh network-manager-openconnect libcurl4-openssl-dev dirsearch ntpdate \
        libpcre3-dev libssh-dev veil eyewitness seclists powershell-empire ltrace ghidra gdb \
		gobuster neo4j bloodhound payloadsallthethings shellter powercat dnscat2 snmp snmp-mibs-downloader -y

    python3 -m pip install --upgrade pip
    pip3 install crackmapexec lsassy pwn impacket bloodhound threader3000 pypykatz kerbrute deathstar-empire aclpwn \
		dsinternals wesng  frida-tools objection ldapdomaindump pylnk3 roadrecon rdpy minikerberos python-ldap "git+https://github.com/ly4k/Certipy.git" \
		"git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump" "git+https://github.com/calebstewart/pwncat.git" "git+https://github.com/zer1t0/certi.git" --upgrade

    gem install evil-winrm
	npm install -g clipboard-cli
	wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | bash

    echo -e "\n${GREEN}[Success]${NC} Install shitload of software \n"
}

wget_tools() {
    
	mkdir -p ${tools_dir}
    mkdir -p ${windows_tools}
    mkdir -p ${other_tools}
	mkdir -p ${mobile_tools}
	mkdir -p ${cloud_tools}

	#-------------------------------------------------------Windows----------------------------------------------------------
	echo -e "${GREEN}Getting Windows tools:${NC}"

	#Windows Misc Utilities 
	echo -e "\tSysInternalsSuite"
	wget -q "https://download.sysinternals.com/files/SysinternalsSuite.zip" -O ${windows_tools}/SysinternalsSuite.zip
	echo -e "\tProcessHacker"
	get_latest_releases "https://github.com/processhacker/processhacker" ${windows_tools}
	echo -e "\tOllydbg"
	wget -q "http://www.ollydbg.de/odbg110.zip" -O ${windows_tools}/odbg110.zip
	echo -e "\tAPI Monitor"
	wget -q "http://www.rohitab.com/download/api-monitor-v2r13-x86-x64.zip" -O ${windows_tools}/api-monitor-v2r13-x86-x64.zip
	echo -e "\tNetscan"
	wget -q "https://www.softperfect.com/download/files/netscan_portable.zip" -O ${windows_tools}/netscan_portable.zip
	
	#C2
	echo -e "\tEmpire"
	wget -q "https://github.com/BC-SECURITY/Empire/archive/master.zip" -O ${windows_tools}/Empire.zip
	echo -e "\tCovenant"
	wget -q "https://github.com/cobbr/Covenant/archive/master.zip" -O ${windows_tools}/Covenant.zip
	echo -e "\tSILENTTRINITY"
	wget -q "https://github.com/byt3bl33d3r/SILENTTRINITY/archive/master.zip" -O ${windows_tools}/SILENTRINITY.zip
	echo -e "\tStarKiller"
	get_latest_releases "https://github.com/BC-SECURITY/Starkiller" ${windows_tools}
	echo -e "\tOffensivePipeline"
	get_latest_releases "https://github.com/Aetsu/OffensivePipeline" ${windows_tools}
	
	#Credentials collection
	echo -e "\tfgdump - wce"
	wget -q "http://foofus.net/goons/fizzgig/fgdump/fgdump-2.1.0-exeonly.zip" -O ${windows_tools}/fgdump-2.1.0-exeonly.zip
	wget -q "https://www.ampliasecurity.com/research/wce_v1_42beta_x32.zip" -O ${windows_tools}/wce_v1_42beta_x32.zip
	wget -q "https://www.ampliasecurity.com/research/wce_v1_42beta_x64.zip" -O ${windows_tools}/wce_v1_42beta_x64.zip
	echo -e "\tNirsoft Tools"
	wget -q "https://www.nirsoft.net/toolsdownload/credentialsfileview-x64.zip" -O ${windows_tools}/credentialsfileview-x64.zip
	wget -q "https://www.nirsoft.net/utils/regfileexport.zip" -O ${windows_tools}/regfileexport.zip
	wget -q "https://www.nirsoft.net/toolsdownload/vaultpasswordview-x64.zip" -O ${windows_tools}/vaultpasswordview-x64.zip
	wget -q "https://www.nirsoft.net/toolsdownload/webbrowserpassview.zip" -O ${windows_tools}/webbrowserpassview.zip
	wget -q "https://www.nirsoft.net/utils/dllexp-x64.zip" -O ${windows_tools}/dllexp-x64.zip

	#Evasion and bypass
	echo -e "\tInsecurePowerShell"
	get_latest_releases "https://github.com/cobbr/InsecurePowerShell/" ${windows_tools}
	echo -e "\tPowerShdll"
	get_latest_releases "https://github.com/p3nt4/PowerShdll" ${windows_tools}

	#PowerShell and Sharp Collections
	echo -e "\tPowerSploit"
	wget -q "https://github.com/PowerShellMafia/PowerSploit/archive/master.zip" -O ${windows_tools}/PowerSploit.zip
	echo -e "\tSharpSploit"
	wget -q "https://github.com/cobbr/SharpSploit/archive/master.zip" -O ${windows_tools}/SharpSploit.zip
	echo -e "\tNishang"
	wget -q "https://github.com/samratashok/nishang/archive/master.zip" -O ${windows_tools}/nishang.zip
	echo -e "\timpacket - cme"
	get_latest_releases "https://github.com/SecureAuthCorp/impacket/" ${windows_tools}
	get_latest_releases "https://github.com/byt3bl33d3r/CrackMapExec" ${windows_tools}
	get_latest_releases "https://github.com/MichaelKCortez/CrackMapExecWin" ${windows_tools}
	echo -e "\toleviewdotnet"
	get_latest_releases "https://github.com/tyranid/oleviewdotnet" ${windows_tools}

	#----------------------------------------------------------AD------------------------------------------------------------
	echo -e "${GREEN}Getting AD tools:${NC}"

	#AD Module
	echo -e "\tADModule"
	wget -q "https://github.com/samratashok/ADModule/archive/master.zip" -O ${windows_tools}/ADModule.zip

	#AD Collection
	echo -e "\tANSSI s AD Control Paths"
	get_latest_releases "https://github.com/ANSSI-FR/AD-control-paths" ${windows_tools}
	echo -e "\tPingCastle"
	get_latest_releases "https://github.com/vletoux/pingcastle" ${windows_tools}
	echo -e "\tThycoticWeakPasswordFinder"
	wget -q "https://d36zgw9sidnotm.cloudfront.net/FreeTools/ThycoticWeakPasswordFinder.zip" -O ${windows_tools}/ThycoticWeakPasswordFinder.zip
	echo -e "\tgo-windapsearch"
	get_latest_releases "https://github.com/ropnop/go-windapsearch" ${windows_tools}
	echo -e "\tadmpwd"
	get_latest_releases "https://github.com/GreyCorbel/admpwd" ${windows_tools}

	#------------------------------------------------Mobile-------------------------------------------------------
	echo -e "${GREEN}Getting Mobile tools...${NC}"
	echo -e "\tcycript"
	wget -q "https://cydia.saurik.com/api/latest/3" -O ${mobile_tools}/cycript.zip
	echo -e "\tMobSF"
	wget -q "https://github.com/MobSF/Mobile-Security-Framework-MobSF/archive/master.zip" -O ${mobile_tools}/Mobile-Security-Framework-MobSF.zip
	
	#------------------------------------------------Cloud-------------------------------------------------------
	echo -e "${GREEN}Getting Cloud tools...${NC}"
	echo -e "\tStormspotter"
	get_latest_releases "https://github.com/Azure/Stormspotter/" ${cloud_tools}
	echo -e "\tScubaGear"
	wget -q "https://github.com/cisagov/ScubaGear/archive/master.zip" -O ${cloud_tools}/ScubaGear.zip

	#------------------------------------------------Other-------------------------------------------------------
	echo -e "${GREEN}Getting Other tools...${NC}"
	echo -e "\tChisel"
	get_latest_releases "https://github.com/jpillora/chisel" ${other_tools}
	echo -e "\tpcileech"
	get_latest_releases "https://github.com/ufrisk/pcileech" ${other_tools}
	echo -e "\taquatone"
	get_latest_releases "https://github.com/michenriksen/aquatone" ${other_tools}
	echo -e "\tdnscat"
	wget -q "https://downloads.skullsecurity.org/dnscat2/dnscat2-v0.07-client-x64.tar.bz2" -O ${other_tools}/dnscat2-v0.07-client-x64.tar.bz2
	wget -q "https://downloads.skullsecurity.org/dnscat2/dnscat2-v0.07-client-win32.zip" -O ${other_tools}/dnscat2-v0.07-client-win32.zip
	echo -e "\tHeidiSQL"
	wget -q "https://www.heidisql.com/downloads/releases/HeidiSQL_11.3_64_Portable.zip" -O ${other_tools}/HeidiSQL_11.3_64_Portable.zip
	echo -e "\tysoserial"
	wget -q "https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar" -O ${other_tools}/ysoserial-master-SNAPSHOT.jar
	wget -q "https://github.com/pwntester/ysoserial.net/releases/download/v1.34/ysoserial-1.34.zip" -O ${other_tools}/ysoserial-1.34.zip
	
	chown $low_priv_user:$low_priv_user -R $tools_dir
}

#### Calling functions
system_update                        || { echo -e "\n\n${RED}[Failure]${NC} System update failed.. exiting script!\n"; exit 1; }
install_ftp                          || { echo -e "\n\n${RED}[Failure]${NC} ftp install failed.. exiting script!\n"; exit 1; }
install_smb                          || { echo -e "\n\n${RED}[Failure]${NC} smb install failed.. exiting script!\n"; exit 1; }
install_shitload_software            || { echo -e "\n\n${RED}[Failure]${NC} Shitload of software install failed.. exiting script!\n"; exit 1; }
create_aliases                       || { echo -e "\n\n${RED}[Failure]${NC} Creating aliases failed.. exiting script!\n"; exit 1; }
copy_i3_config_files                 || { echo -e "\n\n${RED}[Failure]${NC} i3 config files copy failed.. exiting script!\n"; exit 1; }
#wget_tools                           || { echo -e "\n\n${RED}[Failure]${NC} Download useful tools failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} finished! \n"
