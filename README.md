# Kali dot-files

Personal configuration and setup scripts for Kali Linux pentesting VMs.

## Contents

| File / Directory | Description |
|---|---|
| `install_init.sh` | Base system setup — essential packages, FTP/SMB servers, zsh with oh-my-zsh + starship, aliases, i3 config |
| `install_tools.sh` | Pentesting tools — pipx packages, binary downloads (Windows/AD/Mobile/Cloud/Other) |
| `dot-files/i3/` | i3wm config and i3blocks status bar config |
| `dot-files/scripts/` | Utility scripts (lock screen) |

## Usage

```bash
# Run as root or with sudo, from the repo root directory
sudo ./install_init.sh   # Base system + zsh + aliases + i3
sudo ./install_tools.sh  # Pentesting tools
```

## Zsh Setup

The `install_init.sh` script installs a modern terminal environment:

- **[oh-my-zsh](https://ohmyz.sh/)** — zsh framework
- **[zsh-autosuggestions](https://github.com/zsh-users/zsh-autosuggestions)** — fish-like suggestions
- **[zsh-syntax-highlighting](https://github.com/zsh-users/zsh-syntax-highlighting)** — command syntax highlighting
- **[starship](https://starship.rs/)** — fast, customizable prompt

Configured for both `kali` user and `root`.
