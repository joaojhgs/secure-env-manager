# 🔐 Secure Environment Manager

A toolkit for creating development environments with optional **LUKS-encrypted storage**, a separate developer account, and separate-user rootless Docker using Distrobox and rootless Podman. These controls are not a SOC2 certification or a complete hostile-code sandbox.

## 🎯 Purpose

This project separates development storage and Docker privileges while retaining desktop integration (GUI apps, audio, video conferencing). Distrobox deliberately integrates with its host; see [worker access and remaining security boundaries](docs/worker-access.md) before connecting an externally hosted agent controller.

### Key Features

- **🔒 Optional LUKS Encryption** - Environment storage can use encrypted sparse images
- **🏠 Host Filesystem Allowlist** - Dedicated developer home; no ambient host-root/home/tmp binds
- **🛡️ Explicit Capability Configuration** - Not equivalent to a fully sandboxed container
- **🐳 Separate Rootless Docker** - Locked non-root host builder identity; no host-root Docker proxy or docker-group grant
- **🔑 Restricted SSH Jump** - Transport-only host account; inner SSH owns terminals and files
- **🎨 Full Desktop Integration** - X11 display, audio (PulseAudio/PipeWire), webcam
- **📦 Isolated Storage** - Each environment has its own encrypted persistent storage
- **🔑 SSH Key Generation** - Automatic per-environment SSH keys for git operations
- **🌐 Browser Security** - Chromium sandbox enabled (no `--no-sandbox` flag)

## 📋 Requirements

### Host System
- Linux with systemd (tested on Ubuntu 22.04+, Fedora 38+)
- Podman (rootless; the manager rejects root-owned create/setup operations)
- Distrobox 1.5+
- Python 3.11+, GPG, zstd (filesystem policy, verification and encrypted backups)
- cryptsetup (for LUKS encryption)
- X11 display server
- PulseAudio or PipeWire (for audio)
- Host Docker rootless tools (`dockerd-rootless.sh`, `rootlesskit`, `newuidmap`, `newgidmap`, `slirp4netns`), `socat`, systemd user services
- Kernel/filesystem/util-linux support for `X-mount.idmap`; installation tests this on a small private fixture and refuses a chmod/chown/ACL fallback

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
./manage-safe-environement.sh create work
```

To place the environment on a dedicated ext4 disk instead of `/opt`:

```bash
SEM_STORAGE_ROOT=/mnt/hdd2/secure-env-manager/environments \
SEM_IMAGE_ROOT=/mnt/hdd2/secure-env-manager/images \
./manage-safe-environement.sh create work
```

To snapshot and transfer an existing rootless Distrobox without deleting its
source data:

```bash
./manage-safe-environement.sh migrate personal /mnt/hdd2/secure-env-manager
```

### Transfer between computers

Create a password-encrypted portable bundle containing the OCI root filesystem,
the isolated developer home, container metadata, and checksums:

```bash
./manage-safe-environement.sh export personal /mnt/backup/personal.sem.tar.gpg
```

Copy it over SSH and import it on another Linux computer:

```bash
./manage-safe-environement.sh send /mnt/backup/personal.sem.tar.gpg user@new-pc:/srv/transfers/
./manage-safe-environement.sh import /srv/transfers/personal.sem.tar.gpg /mnt/hdd2/secure-env-manager personal
```

Exports can instead be encrypted to a GPG public key with `--recipient`, or use
`--passphrase-file /path/to/0600-owned-key` for noninteractive backups. Version 2
compresses both the OCI image and developer home; import remains compatible with
version 1. `--exclude-file` accepts an explicit list of verified regenerable paths
relative to the developer home, stored in the encrypted bundle for transparency.
`--stream-home` uses version 3 to stream/compress/encrypt the home directly,
avoiding a second full home archive in staging. Import accepts all three versions
and restores on the selected Linux filesystem, not host tmpfs.
Private
agent credentials may be present in the developer home, so unencrypted portable
bundles are intentionally unsupported. Import preserves container-relative file
ownership even when the two computers use different Podman subordinate UID/GID
ranges, and refuses to overwrite an existing container or developer home.

This will:
- Create a 100GB sparse LUKS-encrypted image (optional)
- Create a Distrobox container with Ubuntu 24.04
- Remove Distrobox's implicit host root/home/tmp filesystem mounts
- Set up the `developer` user with isolated home
- Generate environment-specific SSH keys
- Install the permission bridge for GUI apps

Creation automatically provisions a locked `sem-build-<environment>` host user,
private rootless Docker storage/socket and a private ID-mapped workspace view.
Bind mounts keep `/home/developer` paths and developer file ownership. Missing
rootless prerequisites fail closed; the old world-writable host-root proxy is
never created. Missing prerequisites are reported, not installed by an unpinned
remote installation script. See [setup details](docs/worker-access.md).

For an existing environment, additive setup is available without recreation:

```bash
./manage-safe-environement.sh setup-docker personal
```

If distroboxes deliberately share the same developer identity, explicitly accept
cross-environment data/API access:

```bash
./manage-safe-environement.sh setup-docker university --allow-shared-developer
# For a new installation on a shared-identity host:
SEM_ALLOW_SHARED_DEVELOPER=1 ./manage-safe-environement.sh create university
```

This does **not** revoke an existing shared host-root Docker proxy or make broad
host mounts safe. Existing shells keep their old Docker exports until reopened;
revoking old access is a separate, deliberately scheduled step.

At the end of creation, the manager asks separately whether to configure
key-only SSH and whether to configure the jump proxy. The jump proxy starts a
stopped Distrobox on the first SSH connection, waits for its SSH daemon, and
then forwards the connection. Existing environments can be configured with:

```bash
./manage-safe-environement.sh setup-ssh personal
```

The generated local alias is `sem-<host>-<environment>`. To reach the box from
another machine through its host, use the printed `ProxyCommand` in that
client's SSH configuration. The restricted jump account tunnels through Podman, so it also works
for environments with isolated networking. Each box receives a unique
loopback-only port and accepts only the generated `developer` key; password and
root SSH logins are disabled. Host and inner SSH public keys are pinned locally;
the outer `orca-jump` account has no host shell, PTY or arbitrary forwarding.
Never use or transfer the unrestricted human-host key for a VPS agent controller.

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

The diagram below illustrates the intended developer-account separation, not
proof of actual encryption, hidden alternate host paths, or container-root
isolation. Audit the running container configuration; see the security notes.

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
│  │   └── /host_mask → Private administrative home        │  │
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
│  │  • Explicit capabilities/devices retained for integration││
│  │  • --ipc=private (isolated IPC namespace)               ││
│  │  • --unshare-process (PID namespace isolation)          ││
│  │  • Host root/home/tmp binds removed by mount allowlist ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Management Commands

### Environment Lifecycle
```bash
# Create new environment
./manage-safe-environement.sh create <env-name>

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

### Advanced Usage Examples

**Installing Custom Applications:**
You can deploy your own extensions, binaries, and `.deb` files using `setup-apps.sh`:
```bash
# Install a .deb package that is on your host
./setup-apps.sh <env-name> --deb /path/to/app.deb

# Run an external script to install dependencies
./setup-apps.sh <env-name> --script /path/to/install.sh

# Run a specific command
./setup-apps.sh <env-name> --cmd "sudo apt-get install htop -y"

# Create a desktop shortcut for an app already inside the container
./setup-apps.sh <env-name> --launcher-only
```
*(For a deeper dive on customizing default apps, check [docs/setup-apps-customization.md](docs/setup-apps-customization.md))*

**Mounting Encrypted Environments:**
After a reboot of the host machine, the container's encrypted image won't be mapped. Before starting your applications, mount it automatically via:
```bash
# Prompt for the environment's LUKS passphrase to unlock the volume
sudo ./manage-safe-environement.sh mount <env-name>
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
- Host root/home/tmp binds removed for newly created or explicitly migrated boxes; verify actual mounts on older boxes.
- ✅ No `--privileged` flag (capability-based restrictions)
- ✅ Browser sandboxing enabled
- ✅ X11 access restricted to current user only
- No host Docker group; the scoped Docker API belongs to a separate rootless builder identity.
- ✅ Encrypted storage at rest (LUKS)

### Capabilities Granted
| Capability | Purpose |
|------------|---------|
| `SYS_PTRACE` | Debugging tools (strace, gdb) |
| `SETUID` | sudo functionality |
| `SETGID` | Group switching for sudo |
| `SYS_ADMIN` and other configured capabilities | Existing Distrobox integration; preserved, not a hostile-code isolation guarantee |

### Attack Surface Reduction
- IPC namespace isolated (`--ipc=private`)
- PID namespace isolated (`--unshare-process`)
- Device access explicitly enumerated
- No raw network namespace access

This is a filesystem-exposure reduction, not a complete sandbox. Retained X11,
audio, devices, capabilities and host networking remain deliberate attack
surfaces. The architecture diagram does not certify existing boxes;
run the mount/root/developer verification described in [filesystem-boundary.md](docs/filesystem-boundary.md).

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
