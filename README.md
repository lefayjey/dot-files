# Kali dot-files

Personal configuration and setup scripts for Kali Linux pentesting VMs.  
Theme: **Catppuccin Macchiato** · Font: **JetBrains Mono**

## Repository layout

```
.
├── i3/
│   ├── config            # i3wm window manager config
│   └── i3blocks.conf     # i3blocks status bar config
├── picom/
│   └── picom.conf        # Picom compositor (blur, shadows, rounded corners)
├── rofi/
│   └── config.rasi       # Rofi application launcher theme
├── scripts/
│   └── lock_screen.sh    # i3lock-color lock screen with frosted blur
├── starship/
│   └── starship.toml     # Starship prompt config
├── qterminal/
│   └── kali.colorscheme  # Qterminal color scheme
├── Xresources            # Terminal colors (xterm / urxvt / xrdb)
├── install_init.sh       # Base system setup
└── install_tools.sh      # Pentesting tools setup
```

## Usage

```bash
# Run as root or with sudo, from the repo root directory
sudo ./install_init.sh   # Base system + zsh + aliases + i3 + picom
sudo ./install_tools.sh  # Pentesting tools
```

The scripts auto-detect the repo directory, so they work from any `$PWD`.

## What `install_init.sh` sets up

| Step | Details |
|---|---|
| **Packages** | i3blocks, rofi, picom, i3lock-color, feh, flameshot, scrot, imagemagick, zsh, tmux, fonts, … |
| **FTP / SMB** | Pure-FTPd + Samba share in `~/ftp` and `~/smb` |
| **Zsh** | oh-my-zsh + autosuggestions + syntax-highlighting + starship prompt |
| **Tmux** | oh-my-tmux with pentest status bar (tun0/eth0 IP) |
| **Aliases** | Pentest shortcuts (`www`, `smb`, `vpnip`, `htb`, `thm`, docker helpers, …) |
| **Pro aliases** | `listener`, `revshell`, `target`, `rdp`, `encode64`, `webshell`, `loot`, … |
| **i3** | Full config with gaps, Catppuccin colors, rofi launcher, power menu, vim keys |
| **Picom** | Dual-kawase blur, shadows, rounded corners |
| **Lock screen** | Frosted blur screenshot + i3lock-color ring with clock display |
| **Wallpaper** | `feh --bg-fill ~/.wallpaper` (falls back to solid `#181926`) |
| **VM resume** | Systemd sleep hook re-applies `setxkbmap ch` + timezone on suspend/resume |

All configs are deployed to both `kali` user and `root`.

## i3 key bindings

| Key | Action |
|---|---|
| `$mod+Return` | Terminal (qterminal) in current dir |
| `$mod+Shift+Return` | Terminal (default dir) |
| `$mod+d` | Rofi app launcher |
| `$mod+Shift+d` | Rofi run prompt |
| `$mod+Tab` | Rofi window switcher |
| `$mod+l` | Lock screen |
| `$mod+Shift+s` | Flameshot screenshot |
| `$mod+Shift+e` | Power menu (lock / exit / reboot / shutdown) |
| `$mod+r` | Resize mode |
| `$mod+h/j/k` | Focus left/down/up (vim-style) |
| `$mod+Shift+h/j/k/l` | Move window (vim-style) |

## Zsh setup

- **[oh-my-zsh](https://ohmyz.sh/)** — zsh framework
- **[zsh-autosuggestions](https://github.com/zsh-users/zsh-autosuggestions)** — fish-like suggestions
- **[zsh-syntax-highlighting](https://github.com/zsh-users/zsh-syntax-highlighting)** — command syntax highlighting
- **[starship](https://starship.rs/)** — fast, customizable prompt

## Pro pentesting aliases & functions

| Command | Description |
|---|---|
| `target <ip>` | Set/display current target IP (shown in prompt 🎯) |
| `listener <port>` | `rlwrap nc -lvnp <port>` |
| `revshell [ip] [port]` | Generate bash reverse shell + base64 encoded version |
| `rdp <ip>` | xfreerdp with clipboard + dynamic resolution |
| `loot` | Create standard loot directory structure |
| `webshell` | Copy PHP reverse shell to current dir |
| `encode64` / `decode64` | Base64 encode/decode |
| `urlencode <str>` | URL-encode a string |
| `headers <url>` | Quick HTTP header check |
| `pse <target>` | CrackMapExec SMB shortcut |
| `ts` | Print timestamp (`YYYYMMDD_HHMMSS`) |

## Setting a wallpaper

```bash
# Copy your image and restart i3
cp /path/to/wallpaper.png ~/.wallpaper
# $mod+Shift+r to restart i3
```
