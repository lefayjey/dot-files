#!/bin/bash -e
# Author: lefayjey
# last updated: 24/02/2026

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

low_priv_user="kali"

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo or as root"
    exit 1
fi

update_install() {
    echo -e "\n${BLUE}[Initiate]${NC} Install essential software\n"
    apt update && apt upgrade -y
    apt install -y i3blocks i3lock rofi suckless-tools htop xcwd flameshot sshfs xclip \
        ghidra filezilla ntpsec-ntpdate rlwrap 2to3 gobuster eyewitness seclists krb5-user \
        tigervnc-viewer jadx gdb ltrace dos2unix curl wget git zsh \
        picom fonts-jetbrains-mono fonts-powerline \
        tmux cool-retro-term imagemagick
    echo -e "\n${GREEN}[Success]${NC} Install essential software\n"
}

install_ftp() {
    echo -e "\n${BLUE}[Initiate]${NC} Installing FTP\n"
    apt install -y pure-ftpd
    pure-pw useradd "$low_priv_user" -u "$low_priv_user" -d "/home/$low_priv_user/ftp"
    pure-pw mkdb
    ln -sf /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/60pdb
    mkdir -p "/home/$low_priv_user/ftp"
    chown -R "$low_priv_user:$low_priv_user" "/home/$low_priv_user/ftp"
    /etc/init.d/pure-ftpd restart
    echo -e "\n${GREEN}[Success]${NC} Installing FTP\n"
}

install_smb() {
    echo -e "\n${BLUE}[Initiate]${NC} Installing SMB\n"
    apt install -y samba
    mv /etc/samba/smb.conf /etc/samba/smb.conf.old
    cat > /etc/samba/smb.conf <<EOF
[share]
path = /home/$low_priv_user/smb
browseable = yes
read only = no
EOF
    smbpasswd -a "$low_priv_user"
    systemctl start smbd
    systemctl start nmbd
    mkdir -p "/home/$low_priv_user/smb"
    chown -R "$low_priv_user:$low_priv_user" "/home/$low_priv_user/smb"
    echo -e "\n${GREEN}[Success]${NC} Installing SMB\n"
}

install_zsh() {
    echo -e "\n${BLUE}[Initiate]${NC} Modernize zsh terminal\n"

    # Install oh-my-zsh for low_priv_user
    if [ ! -d "/home/$low_priv_user/.oh-my-zsh" ]; then
        sudo -u "$low_priv_user" sh -c \
            'RUNZSH=no KEEP_ZSHRC=yes sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"'
    fi

    # Install oh-my-zsh for root
    if [ ! -d "/root/.oh-my-zsh" ]; then
        RUNZSH=no KEEP_ZSHRC=yes sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    fi

    # Install zsh plugins for low_priv_user
    local user_custom="/home/$low_priv_user/.oh-my-zsh/custom"
    if [ ! -d "$user_custom/plugins/zsh-autosuggestions" ]; then
        sudo -u "$low_priv_user" git clone https://github.com/zsh-users/zsh-autosuggestions "$user_custom/plugins/zsh-autosuggestions"
    fi
    if [ ! -d "$user_custom/plugins/zsh-syntax-highlighting" ]; then
        sudo -u "$low_priv_user" git clone https://github.com/zsh-users/zsh-syntax-highlighting "$user_custom/plugins/zsh-syntax-highlighting"
    fi

    # Install zsh plugins for root
    local root_custom="/root/.oh-my-zsh/custom"
    if [ ! -d "$root_custom/plugins/zsh-autosuggestions" ]; then
        git clone https://github.com/zsh-users/zsh-autosuggestions "$root_custom/plugins/zsh-autosuggestions"
    fi
    if [ ! -d "$root_custom/plugins/zsh-syntax-highlighting" ]; then
        git clone https://github.com/zsh-users/zsh-syntax-highlighting "$root_custom/plugins/zsh-syntax-highlighting"
    fi

    # Install starship prompt
    if ! command -v starship &>/dev/null; then
        curl -sS https://starship.rs/install.sh | sh -s -- -y
    fi

    # Configure starship with a pentest-friendly preset
    mkdir -p "/home/$low_priv_user/.config"
    mkdir -p "/root/.config"
    local dotfile_dir="./dot-files"
    cp "$dotfile_dir/starship/starship.toml" "/home/$low_priv_user/.config/starship.toml"
    chown "$low_priv_user:$low_priv_user" "/home/$low_priv_user/.config/starship.toml"
    cp "$dotfile_dir/starship/starship.toml" "/root/.config/starship.toml"

    echo -e "\n${GREEN}[Success]${NC} Modernize zsh terminal\n"
}

install_tmux() {
    echo -e "\n${BLUE}[Initiate]${NC} Install oh-my-tmux\n"

    # Install oh-my-tmux for low_priv_user
    if [ ! -d "/home/$low_priv_user/.tmux" ]; then
        sudo -u "$low_priv_user" git clone https://github.com/gpakosz/.tmux.git "/home/$low_priv_user/.tmux"
        sudo -u "$low_priv_user" ln -sf "/home/$low_priv_user/.tmux/.tmux.conf" "/home/$low_priv_user/.tmux.conf"
        sudo -u "$low_priv_user" cp "/home/$low_priv_user/.tmux/.tmux.conf.local" "/home/$low_priv_user/.tmux.conf.local"
    fi

    # Install oh-my-tmux for root
    if [ ! -d "/root/.tmux" ]; then
        git clone https://github.com/gpakosz/.tmux.git /root/.tmux
        ln -sf /root/.tmux/.tmux.conf /root/.tmux.conf
        cp /root/.tmux/.tmux.conf.local /root/.tmux.conf.local
    fi

    # Add pentest IP display to tmux status bar (alh4zr3d style)
    local tmux_snippet='
# -- pentest status bar (tun0 > eth0 IP) ------------------------------------
tmux_conf_theme_status_right_prefix="#{?#{==:#{pane_current_command},ssh},#[fg=yellow] ssh,} "
tmux_conf_theme_status_right=" #{?#{!=:#{b:pane_current_path},},#{b:pane_current_path},} | #(ip -4 addr show tun0 2>/dev/null | grep -oP "(?<=inet )\S+" | cut -d/ -f1 || ip -4 addr show eth0 2>/dev/null | grep -oP "(?<=inet )\S+" | cut -d/ -f1 || echo no-ip) | %R %d-%b"
'
    for conf in "/home/$low_priv_user/.tmux.conf.local" "/root/.tmux.conf.local"; do
        if ! grep -q "pentest status bar" "$conf" 2>/dev/null; then
            echo "$tmux_snippet" >> "$conf"
        fi
    done

    echo -e "\n${GREEN}[Success]${NC} Install oh-my-tmux\n"
}


_write_aliases() {
    # Usage: _write_aliases <zshrc_path> <use_sudo>
    local zshrc="$1"
    local prefix="$2"  # "sudo " for low_priv_user, "" for root

    cat >> "$zshrc" <<ALIASES

## Pentest aliases
alias www="python3 -m http.server 8000 --directory /opt/PentestTools/"
alias wwwhere="python3 -m http.server 8000"
alias smb="python3 \$(which smbserver.py) TOOLS /opt/PentestTools/ -smb2 -username username -password password"
alias smb_here="python3 \$(which smbserver.py) SHARE \$(pwd) -smb2 -username username -password password"
alias htb="${prefix}openvpn /opt/CTF/hackthebox/lab_cerebro11.ovpn"
alias thm="${prefix}openvpn /opt/CTF/tryhackme/cerebro11.ovpn"
alias vpnip="/sbin/ifconfig tun0 | grep 'inet ' | cut -d ' ' -f 10"
alias serv="sudo service apache2 start; sudo service smbd start; sudo service nmbd start; sudo service pure-ftpd start; sudo service ssh start"
alias dockershell="sudo docker run --rm -i -t --entrypoint=/bin/bash"
alias dockershellsh="sudo docker run --rm -i -t --entrypoint=/bin/sh"
alias clipboard="xclip -selection clipboard"

function dockershellhere() {
    dirname=\${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/bash -v "\$(pwd):/\${dirname}" -w "/\${dirname}" "\$@"
}

function dockershellshhere() {
    dirname=\${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/sh -v "\$(pwd):/\${dirname}" -w "/\${dirname}" "\$@"
}
ALIASES
}

_configure_zshrc() {
    # Usage: _configure_zshrc <zshrc_path>
    local zshrc="$1"

    # Set oh-my-zsh plugins
    if grep -q "^plugins=" "$zshrc"; then
        sed -i 's/^plugins=.*/plugins=(git sudo zsh-autosuggestions zsh-syntax-highlighting)/' "$zshrc"
    else
        echo 'plugins=(git sudo zsh-autosuggestions zsh-syntax-highlighting)' >> "$zshrc"
    fi

    # Add starship init at the end if not already present
    if ! grep -q 'eval "$(starship init zsh)"' "$zshrc"; then
        echo '' >> "$zshrc"
        echo '# Starship prompt' >> "$zshrc"
        echo 'eval "$(starship init zsh)"' >> "$zshrc"
    fi

    # Add useful zsh options if not present
    if ! grep -q "HIST_IGNORE_DUPS" "$zshrc"; then
        cat >> "$zshrc" <<'ZSHOPTS'

# Modern zsh options
setopt HIST_IGNORE_DUPS
setopt HIST_IGNORE_SPACE
setopt SHARE_HISTORY
setopt AUTO_CD
setopt CORRECT
HISTSIZE=50000
SAVEHIST=50000
ZSHOPTS
    fi
}

create_aliases() {
    echo -e "\n${BLUE}[Initiate]${NC} Configuring aliases and zsh\n"

    # Prepare VM mounting script
    cat > /usr/local/sbin/vm-mount <<'EOF'
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

vmware-hgfsclient | while read -r folder; do
    vmwpath="/mnt/hgfs/${folder}"
    echo "[i] Mounting ${folder}   (${vmwpath})"
    sudo mkdir -p "${vmwpath}"
    sudo umount -f "${vmwpath}" 2>/dev/null
    sudo vmhgfs-fuse -o allow_other -o auto_unmount ".host:/${folder}" "${vmwpath}"
done
sleep 2s

for i in /mnt/hgfs/$(vmware-hgfsclient)/*/; do
    ln -s "$i" /opt 2>/dev/null
done
EOF
    chmod +x /usr/local/sbin/vm-mount

    # Write aliases for low_priv_user and root
    _write_aliases "/home/$low_priv_user/.zshrc" "sudo "
    _write_aliases "/root/.zshrc" ""

    # Configure zshrc with plugins and starship
    _configure_zshrc "/home/$low_priv_user/.zshrc"
    _configure_zshrc "/root/.zshrc"

    echo -e "\n${GREEN}[Success]${NC} Configuring aliases and zsh\n"
}

copy_i3_config_files() {
    echo -e "\n${BLUE}[Initiate]${NC} Copying i3 config files\n"
    local dotfile_dir="./dot-files"

    mkdir -p /root/.config/i3/
    cp "$dotfile_dir/i3/config" /root/.config/i3/
    dos2unix /root/.config/i3/config
    cp "$dotfile_dir/i3/i3blocks.conf" /root/.config/i3/i3blocks.conf
    dos2unix /root/.config/i3/i3blocks.conf
    chown -R root /root/.config/i3/

    cp "$dotfile_dir/scripts/lock_screen.sh" /usr/bin/lock_screen.sh
    chmod +x /usr/bin/lock_screen.sh

    mkdir -p "/home/$low_priv_user/.config/i3/"
    cp "$dotfile_dir/i3/config" "/home/$low_priv_user/.config/i3/"
    dos2unix "/home/$low_priv_user/.config/i3/config"
    cp "$dotfile_dir/i3/i3blocks.conf" "/home/$low_priv_user/.config/i3/i3blocks.conf"
    dos2unix "/home/$low_priv_user/.config/i3/i3blocks.conf"
    chown -R "$low_priv_user" "/home/$low_priv_user/.config/i3/"

    # Copy rofi config
    mkdir -p /root/.config/rofi/
    cp "$dotfile_dir/rofi/config.rasi" /root/.config/rofi/config.rasi
    mkdir -p "/home/$low_priv_user/.config/rofi/"
    cp "$dotfile_dir/rofi/config.rasi" "/home/$low_priv_user/.config/rofi/config.rasi"
    chown -R "$low_priv_user" "/home/$low_priv_user/.config/rofi/"

    echo -e "\n${GREEN}[Success]${NC} Copying config files\n"
}

#### Calling functions
update_install       || { echo -e "\n\n${RED}[Failure]${NC} Installation of essential software failed.. exiting script!\n"; exit 1; }
install_ftp          || { echo -e "\n\n${RED}[Failure]${NC} FTP install failed.. exiting script!\n"; exit 1; }
install_smb          || { echo -e "\n\n${RED}[Failure]${NC} SMB install failed.. exiting script!\n"; exit 1; }
install_zsh          || { echo -e "\n\n${RED}[Failure]${NC} Zsh modernization failed.. exiting script!\n"; exit 1; }
install_tmux         || { echo -e "\n\n${RED}[Failure]${NC} Tmux install failed.. exiting script!\n"; exit 1; }
create_aliases       || { echo -e "\n\n${RED}[Failure]${NC} Creating aliases failed.. exiting script!\n"; exit 1; }
copy_i3_config_files || { echo -e "\n\n${RED}[Failure]${NC} i3 config files copy failed.. exiting script!\n"; exit 1; }

echo -e "\n${GREEN}[Success]${NC} finished!\n"