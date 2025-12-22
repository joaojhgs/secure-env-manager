# 🔐 Secure Environment Manager

A comprehensive toolkit for creating **LUKS-encrypted, isolated development environments** using Distrobox containers. Designed for secure, SOC2-compliant development workflows where host system isolation is critical.

## 🎯 Purpose

This project solves the challenge of running untrusted or sensitive development workloads in complete isolation from your host system while maintaining full desktop integration (GUI apps, audio, video conferencing).

### Key Features

- **🔒 LUKS Encryption** - All environment data stored in encrypted sparse images
- **🏠 Host Home Masking** - Host's home directory is completely hidden from container
- **🛡️ Capability Restrictions** - Minimal Linux capabilities (no `--privileged`)
- **🎨 Full Desktop Integration** - X11 display, audio (PulseAudio/PipeWire), webcam
- **📦 Isolated Storage** - Each environment has its own encrypted persistent storage
- **🔑 SSH Key Generation** - Automatic per-environment SSH keys for git operations
- **🌐 Browser Security** - Chromium sandbox enabled (no `--no-sandbox` flag)

## 📋 Requirements

### Host System
- Linux with systemd (tested on Ubuntu 22.04+, Fedora 38+)
- Podman (rootless) or Docker
- Distrobox 1.5+
- cryptsetup (for LUKS encryption)
- X11 display server
- PulseAudio or PipeWire (for audio)

### Installation
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install podman distrobox cryptsetup acl

# Install dependencies (Fedora)
sudo dnf install podman distrobox cryptsetup acl

# Clone this repository
git clone https://github.com/joaojhgs/secure-env-manager.git
cd secure-env-manager
chmod +x *.sh
```

## 🚀 Quick Start

### 1. Create a Secure Environment
```bash
sudo ./manage-safe-environement.sh create work
```

This will:
- Create a 100GB sparse LUKS-encrypted image (optional)
- Create a Distrobox container with Ubuntu 24.04
- Configure host home masking
- Set up the `developer` user with isolated home
- Generate environment-specific SSH keys
- Install the permission bridge for GUI apps

### 2. Install Applications
```bash
./setup-apps.sh work
```

This installs and configures:
- **Brave Browser** - Privacy-focused browser
- **Google Chrome** - For compatibility testing  
- **VS Code** - Code editor
- **Cursor** - AI-powered code editor
- Development tools (git, zsh, oh-my-zsh, asdf)

### 3. Launch Applications
After setup, desktop launchers are created:
- `work-brave` - Brave Browser
- `work-chrome` - Google Chrome
- `work-code` - VS Code
- `work-cursor` - Cursor Editor

Or launch manually:
```bash
distrobox enter work -- /usr/local/bin/run-as-dev brave-browser
```

## 📁 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        HOST SYSTEM                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ /home/$USER (chmod 700) - PROTECTED                   │  │
│  │   └── Inaccessible from container                     │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ /opt/isolated_{env}/ - LUKS ENCRYPTED STORAGE         │  │
│  │   ├── /home → Container's /home/developer             │  │
│  │   └── /host_mask → Empty dir masks host home          │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              DISTROBOX CONTAINER                        ││
│  │  ┌─────────────────────────────────────────────────┐   ││
│  │  │ User: developer (UID 1001)                      │   ││
│  │  │ Home: /home/developer (encrypted storage)       │   ││
│  │  │ Groups: audio, video, plugdev (NO docker)       │   ││
│  │  └─────────────────────────────────────────────────┘   ││
│  │                                                         ││
│  │  Security Controls:                                     ││
│  │  • --cap-drop=ALL (minimal capabilities)                ││
│  │  • --ipc=private (isolated IPC namespace)               ││
│  │  • --unshare-process (PID namespace isolation)          ││
│  │  • Host home masked with empty tmpfs                    ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Management Commands

### Environment Lifecycle
```bash
# Create new environment
sudo ./manage-safe-environement.sh create <env-name>

# Delete environment (DESTROYS ALL DATA)
sudo ./manage-safe-environement.sh delete <env-name>

# Mount encrypted storage (after reboot)
sudo ./manage-safe-environement.sh mount <env-name>

# Verify host protection
sudo ./manage-safe-environement.sh verify <env-name>
```

### Application Management
```bash
# Install all apps
./setup-apps.sh <env-name>

# Enter container shell
distrobox enter <env-name>

# Run as developer user
distrobox enter <env-name> -- /usr/local/bin/run-as-dev bash
```

## 🎤📹 Audio/Video Support

### Audio Architecture
The container uses a **socat socket proxy** to bridge PulseAudio:

```
Container (developer UID 1001)
    └── PULSE_SERVER=/tmp/runtime-developer/pulse/native
            │
            ▼
    socat proxy (root in container)
            │
            ▼
Host PulseAudio (/run/user/1000/pulse/native)
```

This solves the UID mismatch between host user (1000) and container developer (1001).

### Video/Webcam Access
Requires a udev rule on the host (created automatically):
```bash
# /etc/udev/rules.d/99-video-container.rules
KERNEL=="video[0-9]*", MODE="0666"
```

### Supported Features
| Feature | Status | Notes |
|---------|--------|-------|
| Speaker Output | ✅ | Via PulseAudio/PipeWire |
| Microphone | ✅ | Via PulseAudio/PipeWire |
| Bluetooth Audio | ✅ | Passes through host |
| Webcam | ✅ | Requires udev rule |
| Screen Sharing | ✅ | X11 access |

## 🛡️ Security Model

### What's Protected
- ✅ Host home directory completely hidden
- ✅ No `--privileged` flag (capability-based restrictions)
- ✅ Browser sandboxing enabled
- ✅ X11 access restricted to current user only
- ✅ No docker group (prevents container escape)
- ✅ Encrypted storage at rest (LUKS)

### Capabilities Granted
| Capability | Purpose |
|------------|---------|
| `SYS_PTRACE` | Debugging tools (strace, gdb) |
| `SETUID` | sudo functionality |
| `SETGID` | Group switching for sudo |

### Attack Surface Reduction
- IPC namespace isolated (`--ipc=private`)
- PID namespace isolated (`--unshare-process`)
- Device access explicitly enumerated
- No raw network namespace access

## 📝 Files Overview

| File | Purpose |
|------|---------|
| `manage-safe-environement.sh` | Environment creation, deletion, encryption |
| `setup-apps.sh` | Application installation and launcher creation |
| `SECURITY_REPORT.md` | Detailed security assessment |

## ⚠️ Important Notes

### After Reboot
If using encryption, you must remount the storage:
```bash
sudo ./manage-safe-environement.sh mount <env-name>
```

### First Run
The first `distrobox enter` may take several minutes to initialize the container.

### SSH Keys
Environment-specific SSH keys are generated at:
```
/home/developer/.ssh/id_ed25519_<env-name>
```
Add the public key to your Git provider.

## 🐛 Troubleshooting

### Audio Not Working
```bash
# Check PulseAudio connection
distrobox enter <env> -- env HOST_UID=$(id -u) /usr/local/bin/run-as-dev pactl info

# Verify socat is installed
distrobox enter <env> -- which socat
```

### Webcam Not Working
```bash
# Check video device permissions on HOST
ls -la /dev/video*

# Should be mode 0666, if not:
sudo chmod 666 /dev/video*
```

### Display Issues
```bash
# Verify X11 authorization
xhost

# Should show: SI:localuser:<your-username>
# If not, run:
xhost +SI:localuser:$(whoami)
```

### Container Won't Start
```bash
# Check if storage is mounted
mount | grep isolated_<env>

# If not mounted:
sudo ./manage-safe-environement.sh mount <env-name>
```

## 📄 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Please ensure any changes maintain or improve the security posture of the environment.

## 📚 References

- [Distrobox Documentation](https://distrobox.it/)
- [Podman Security](https://docs.podman.io/en/latest/markdown/podman.1.html)
- [LUKS Encryption](https://gitlab.com/cryptsetup/cryptsetup)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
