#!/bin/bash -e
# Author: JOF
# last updated: 17/07/2023

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

low_priv_user="kali"

if [ "$EUID" -ne 0 ]
    then echo "Please run with sudo or as root "
    exit
fi

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
    echo 'alias www_here="python3 -m http.server 8000"' >> /home/$low_priv_user/.zshrc
    echo 'alias smb="python3 /usr/local/bin/smbserver.py TOOLS /opt/PentestTools/ -smb2 -username username -password password"' >> /home/$low_priv_user/.zshrc
    echo 'alias smb_here="python3 /usr/local/bin/smbserver.py SHARE `pwd` -smb2 -username username -password password"' >> /home/$low_priv_user/.zshrc
    echo 'alias htb="sudo openvpn /opt/CTF/hackthebox/lab_cerebro11.ovpn"' >> /home/$low_priv_user/.zshrc
    echo 'alias thm="sudo openvpn /opt/CTF/tryhackme/cerebro11.ovpn"' >> /home/$low_priv_user/.zshrc
	echo 'alias vpnip="/sbin/ifconfig tun0 | grep "inet " | cut -d " " -f 10"' >> /home/$low_priv_user/.zshrc
	echo 'alias serv="sudo service apache2 start; sudo service smbd start; sudo service nmbd start; sudo service pure-ftpd start; sudo service ssh start"' >> /home/$low_priv_user/.zshrc

    echo -e "## root's aliases" >> /root/.zshrc
    echo 'alias impacket="/usr/share/doc/python3-impacket/examples"' >> /root/.zshrc
    echo 'alias www="python3 -m http.server 8000 --directory /opt/PentestTools/"; echo "IP: http://$(vpnip):8000\nDirectory: /opt/PentestTools/"' >> /root/.zshrc
    echo 'alias www_here="python3 -m http.server 8000"' >> /root/.zshrc
    echo 'alias smb="python3 /usr/share/doc/python3-impacket/examples/smbserver.py TOOLS /opt/PentestTools/ -smb2 -username username -password password"' >> /root/.zshrc
    echo 'alias smb_here="python3 /usr/local/bin/smbserver.py SHARE `pwd` -smb2 -username username -password password"' >> /root/.zshrc
    echo 'alias htb="openvpn /opt/CTF/hackthebox/lab_cerebro11.ovpn"' >> /root/.zshrc
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

#### Calling functions
install_ftp                          || { echo -e "\n\n${RED}[Failure]${NC} ftp install failed.. exiting script!\n"; exit 1; }
install_smb                          || { echo -e "\n\n${RED}[Failure]${NC} smb install failed.. exiting script!\n"; exit 1; }
create_aliases                       || { echo -e "\n\n${RED}[Failure]${NC} Creating aliases failed.. exiting script!\n"; exit 1; }
copy_i3_config_files                 || { echo -e "\n\n${RED}[Failure]${NC} i3 config files copy failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} finished! \n"