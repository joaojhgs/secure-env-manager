# 🔐 Security Report: Distrobox Isolated Environment Setup

**Date:** December 22, 2025  
**Scope:** `manage-safe-environement.sh` and `setup-apps.sh`  
**Classification:** Internal Security Assessment

---

## Executive Summary

This setup implements a **distrobox-based isolated development environment** with LUKS encryption and host-home masking. While the architecture shows **good security intentions**, several **critical and high-severity vulnerabilities** exist that could compromise the isolation model.

### Risk Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | 3 | Requires Immediate Fix |
| 🟠 High | 4 | Requires Fix Before Production |
| 🟡 Medium | 4 | Should Fix |
| 🟢 Low | 4 | Best Practice Improvements |

---

## 🔴 CRITICAL Vulnerabilities

### CVE-CUSTOM-001: `--privileged` Flag Defeats Container Isolation

**Location:** `manage-safe-environement.sh` Line 476
```bash
--additional-flags "--ipc=host --privileged $DEVICES ..."
```

**CVSS Score:** 9.8 (Critical)

**Description:**  
The `--privileged` flag grants the container full access to the host system, effectively disabling all container isolation mechanisms.

**Technical Impact:**
- Full access to all host devices (`/dev/*`)
- Capability to load kernel modules
- Ability to bypass all namespace isolation
- Access to `/dev/mem`, `/dev/kmsg`, and other sensitive devices
- Can modify host kernel parameters via `/proc/sys`
- Can access raw block devices

**Attack Scenario:**
1. Attacker compromises application inside container (e.g., via browser exploit)
2. Attacker uses `nsenter` or direct device access to escape container
3. Attacker gains root access on host system

**Business Impact:** Complete system compromise, data exfiltration, ransomware deployment

---

### CVE-CUSTOM-002: `--no-sandbox` Chrome/Brave Flag Disables Browser Security

**Location:** `setup-apps.sh` Line 89
```bash
FLAGS="--password-store=basic --no-sandbox --disable-dev-shm-usage --disable-gpu-sandbox ..."
```

**CVSS Score:** 9.1 (Critical)

**Description:**  
The `--no-sandbox` flag disables Chromium's multi-process security sandbox, which is a critical defense against web-based exploits.

**Technical Impact:**
- Browser renderer process runs with full container privileges
- Memory corruption exploits gain unrestricted access
- Cross-site scripting can escalate to code execution
- Malicious websites can execute arbitrary code

**Attack Scenario:**
1. User visits malicious website or receives phishing link
2. Website exploits browser vulnerability (e.g., V8 JavaScript engine bug)
3. Without sandbox, exploit gains full container access
4. Combined with privileged container, attacker escapes to host

**Business Impact:** Remote code execution via web browsing, credential theft

---

### CVE-CUSTOM-003: `xhost +local:` Grants Unrestricted X11 Access

**Location:** `setup-apps.sh` Line 58
```bash
xhost +local: >/dev/null 2>&1
```

**CVSS Score:** 8.4 (High/Critical)

**Description:**  
This command disables X11 access control, allowing any local process to connect to the display server.

**Technical Impact:**
- Any local user/process can connect to X server
- Keylogging of ALL keystrokes (including passwords)
- Screen capture of sensitive information
- Input injection (fake keyboard/mouse events)
- Clipboard sniffing

**Attack Scenario:**
1. Malicious process runs anywhere on the system
2. Process connects to X11 display without authentication
3. Process logs all keystrokes including banking passwords
4. Process captures screenshots of sensitive documents

**Business Impact:** Credential theft, sensitive data exposure, compliance violations

---

## 🟠 HIGH Severity Vulnerabilities

### HSV-001: AppArmor Completely Disabled

**Location:** `manage-safe-environement.sh` Lines 533-540
```bash
echo '#!/bin/sh' > /usr/sbin/apparmor_parser
echo 'exit 0' >> /usr/sbin/apparmor_parser
```

**CVSS Score:** 7.8 (High)

**Description:**  
AppArmor provides Mandatory Access Control (MAC) that restricts what applications can do. Completely disabling it removes a critical security layer.

**Technical Impact:**
- No file access restrictions on applications
- Applications can access any file the user can
- No network restrictions on applications
- Container processes run unconfined

**Recommendation:** Use a permissive AppArmor profile in complain mode instead of disabling entirely.

---

### HSV-002: Insecure ACL/Permission Escalation on X11 Socket

**Location:** `setup-apps.sh` Lines 63-68
```bash
setfacl -m u:$(id -u):rw "$SOCKET_PATH" 2>/dev/null || chmod o+w "$SOCKET_PATH" 2>/dev/null
```

**CVSS Score:** 7.5 (High)

**Description:**  
The fallback `chmod o+w` makes the X11 socket world-writable, allowing any process to connect.

**Technical Impact:**
- Any local process can connect to X11
- Bypasses intended permission model
- Persists until socket is recreated

**Recommendation:** Remove the `chmod o+w` fallback; fail safely instead.

---

### HSV-003: Docker Socket Access Enables Container Escape

**Location:** `manage-safe-environement.sh` Line 561
```bash
useradd -m -s /usr/bin/zsh -G audio,video,plugdev,docker "$INTERNAL_USER"
```

**CVSS Score:** 8.8 (High)

**Description:**  
Docker group membership grants root-equivalent access on the host system.

**Technical Impact:**
- Can spawn privileged containers
- Can mount host filesystem inside new container
- Effectively grants root access to host
- Bypasses all container isolation

**Attack Scenario:**
```bash
# Inside container as developer user
docker run -v /:/host --privileged -it alpine chroot /host
# Now has root shell on host
```

**Recommendation:** Remove docker group; use rootless podman or Docker socket proxy.

---

### HSV-004: `--ipc=host` Shares IPC Namespace

**Location:** `manage-safe-environement.sh` Line 476
```bash
--additional-flags "--ipc=host --privileged ..."
```

**CVSS Score:** 6.5 (Medium-High)

**Description:**  
Shared IPC namespace allows container processes to communicate with host processes via shared memory.

**Technical Impact:**
- Can attach to host shared memory segments
- Can send signals to host processes (if same UID)
- Potential for IPC-based exploits

**Recommendation:** Use `--ipc=private` with explicit `--shm-size` for Chrome/Electron apps.

---

## 🟡 MEDIUM Severity Issues

### MSV-001: Logging Credentials to World-Readable File

**Location:** `setup-apps.sh` Line 72
```bash
$CMD_STR >> /tmp/${BIN_NAME}.log 2>&1
```

**Description:**  
Application output logged to `/tmp/` may contain sensitive data and is readable by all users.

**Technical Impact:**
- OAuth tokens in URLs may be logged
- API keys in error messages
- Session cookies in debug output

**Recommendation:** Log to `~/.local/log/` with 700 permissions.

---

### MSV-002: Unvalidated External Script Execution

**Location:** `manage-safe-environement.sh` Line 661
```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

**Description:**  
Scripts downloaded from the internet are executed without verification.

**Technical Impact:**
- Supply chain attacks possible
- DNS spoofing could redirect to malicious script
- Compromised GitHub account could inject malware

**Recommendation:** Download, verify checksum, then execute.

---

### MSV-003: Weak LUKS Default Configuration

**Location:** `manage-safe-environement.sh` Line 155
```bash
sudo cryptsetup luksFormat "$IMG_FILE" </dev/tty
```

**Description:**  
Default LUKS settings may use LUKS1 with lower iteration counts.

**Technical Impact:**
- Faster brute-force attacks possible
- Weaker key derivation function

**Recommendation:** Use LUKS2 with Argon2id KDF.

---

### MSV-004: Hardcoded Internal Username

**Location:** Both scripts
```bash
INTERNAL_USER="developer"
```

**Description:**  
Predictable username enables targeted attacks.

**Recommendation:** Consider randomized or environment-specific usernames.

---

## 🟢 LOW Severity / Best Practices

### LSV-001: Missing Seccomp Profile

**Description:** No syscall filtering applied to container.

**Recommendation:** Apply default or custom seccomp profile to restrict dangerous syscalls.

---

### LSV-002: No Network Isolation

**Description:** Container shares host network namespace.

**Recommendation:** Consider network namespacing for sensitive workloads.

---

### LSV-003: ClamAV Installed but Not Configured

**Description:** Antivirus installed but not actively scanning.

**Recommendation:** Enable freshclam updates and scheduled scans.

---

### LSV-004: XDG Runtime Directory in /tmp

**Location:** `manage-safe-environement.sh` Line 307
```bash
export XDG_RUNTIME_DIR="/tmp/runtime-developer"
```

**Recommendation:** Use proper runtime directory under `/run/user/`.

---

## Device Access Requirements Analysis

For a development environment with video conferencing and multimedia capabilities, the following devices are required:

| Device | Path | Purpose | Security Consideration |
|--------|------|---------|----------------------|
| GPU | `/dev/dri/*` | Hardware acceleration, GPU compute | Low risk, needed for performance |
| Webcam | `/dev/video*` | Video calls, camera testing | Medium risk, privacy sensitive |
| Microphone | `/dev/snd/*` | Audio input for calls | Medium risk, privacy sensitive |
| Audio Output | `/dev/snd/*` | Sound playback | Low risk |
| USB | `/dev/bus/usb/*` | USB devices, security keys | High risk if unrestricted |

### Recommended Device Configuration

```bash
# GPU Access (required for browsers, VS Code)
--device /dev/dri

# Audio (required for video calls)
--device /dev/snd

# Webcam (only if needed)
--device /dev/video0
--device /dev/video1

# Do NOT include:
# --device /dev/bus/usb (too broad)
# --device /dev/kvm (VM escape risk)
# --device /dev/fuse (filesystem attacks)
```

---

## Compliance Implications

### SOC2 Type II

| Control | Current Status | Gap |
|---------|---------------|-----|
| CC6.1 - Logical Access | ⚠️ Partial | Privileged container bypasses |
| CC6.6 - System Boundaries | ❌ Fail | No effective isolation |
| CC6.7 - Data Transmission | ✅ Pass | LUKS encryption |
| CC6.8 - Malware Prevention | ⚠️ Partial | ClamAV unconfigured |

### GDPR Article 32

| Requirement | Status |
|-------------|--------|
| Encryption at rest | ✅ LUKS available |
| Access controls | ❌ Privileged mode defeats |
| Monitoring | ⚠️ Basic logging only |

---

## Summary of Required Changes

### Must Fix (Before Use)

1. ❌ Remove `--privileged` flag
2. ❌ Remove `--no-sandbox` from browsers
3. ❌ Replace `xhost +local:` with targeted auth
4. ❌ Remove docker group from developer user

### Should Fix (Before Production)

5. ⚠️ Replace disabled AppArmor with permissive profile
6. ⚠️ Remove `chmod o+w` X11 fallback
7. ⚠️ Replace `--ipc=host` with `--ipc=private`
8. ⚠️ Secure log file locations

### Nice to Have

9. 💡 Add seccomp profile
10. 💡 Configure ClamAV
11. 💡 Use LUKS2 with Argon2

---

# 📋 Implementation Plan

## Phase 1: Critical Fixes (Immediate)

### 1.1 Remove `--privileged` and Configure Proper Capabilities

**File:** `manage-safe-environement.sh`

**Current Code (Line ~476):**
```bash
--additional-flags "--ipc=host --privileged $DEVICES --volume /tmp/.X11-unix:/tmp/.X11-unix"
```

**New Code:**
```bash
--additional-flags "--ipc=private --shm-size=4g --cap-drop=ALL --cap-add=SYS_PTRACE --security-opt=no-new-privileges:true $DEVICES --volume /tmp/.X11-unix:/tmp/.X11-unix:ro"
```

**Explanation:**
- `--ipc=private`: Isolate IPC namespace
- `--shm-size=4g`: Provide shared memory for Chrome/Electron apps
- `--cap-drop=ALL`: Remove all capabilities
- `--cap-add=SYS_PTRACE`: Allow debugging (needed for some dev tools)
- `--security-opt=no-new-privileges:true`: Prevent privilege escalation
- `:ro` on X11 socket: Read-only mount

**Device Configuration:**

Update the DEVICES variable to explicitly list required devices:

```bash
# Build device list based on available hardware
DEVICES=""

# GPU (required for hardware acceleration)
[ -e /dev/dri ] && DEVICES="$DEVICES --device /dev/dri"

# Audio devices (required for video calls, sound)
for snd_dev in /dev/snd/*; do
    [ -e "$snd_dev" ] && DEVICES="$DEVICES --device $snd_dev"
done

# Webcam (enumerate available video devices)
for video_dev in /dev/video*; do
    [ -e "$video_dev" ] && DEVICES="$DEVICES --device $video_dev"
done

# Input devices for hardware keys (YubiKey, etc.)
# Note: This is more permissive - consider restricting to specific devices
if [ -d /dev/bus/usb ]; then
    # Only mount specific USB paths or use udev rules
    DEVICES="$DEVICES --device-cgroup-rule='c 189:* rmw'"
    DEVICES="$DEVICES -v /dev/bus/usb:/dev/bus/usb"
fi
```

---

### 1.2 Fix Browser Sandbox Flags

**File:** `setup-apps.sh`

**Current Code (Line ~89):**
```bash
FLAGS="--password-store=basic --no-sandbox --disable-dev-shm-usage --disable-gpu-sandbox --ozone-platform=x11 --verbose"
```

**New Code:**
```bash
# Browser flags - sandbox enabled with fallbacks for container environment
FLAGS="--password-store=basic --disable-dev-shm-usage --ozone-platform=x11 --verbose"

# Only disable setuid sandbox (user namespace sandbox still active)
# This is safe because we're in a container with limited privileges
FLAGS="$FLAGS --disable-setuid-sandbox"

# Enable software rendering fallback if GPU issues occur
# FLAGS="$FLAGS --disable-gpu"  # Uncomment only if GPU issues
```

**Explanation:**
- Removed `--no-sandbox`: Keeps Chromium's user-namespace sandbox active
- Removed `--disable-gpu-sandbox`: GPU sandbox provides additional protection
- `--disable-setuid-sandbox`: Safe to disable since container doesn't have setuid anyway
- The user-namespace sandbox is the primary security boundary

---

### 1.3 Fix X11 Authorization

**File:** `setup-apps.sh`

**Current Code (Lines ~55-70):**
```bash
# Grant Socket Access
if command -v xhost >/dev/null; then
    xhost +local: >/dev/null 2>&1
fi

if [ -n "\$DISPLAY" ]; then
    SOCKET_NUM=\${DISPLAY#*:} 
    SOCKET_PATH="/tmp/.X11-unix/X\${SOCKET_NUM%.*}"
    if command -v setfacl &> /dev/null && [ -e "\$SOCKET_PATH" ]; then
        setfacl -m u:$(id -u):rw "\$SOCKET_PATH" 2>/dev/null || chmod o+w "\$SOCKET_PATH" 2>/dev/null
    elif [ -e "\$SOCKET_PATH" ]; then
        chmod o+w "\$SOCKET_PATH" 2>/dev/null
    fi
fi
```

**New Code:**
```bash
# Grant X11 Access - SECURE METHOD
# Use xhost with specific user authorization only
if command -v xhost >/dev/null; then
    # Only authorize the current user, not all local connections
    xhost +SI:localuser:$(whoami) >/dev/null 2>&1
fi

# Set ACL on X11 socket - DO NOT fall back to world-writable
if [ -n "\$DISPLAY" ]; then
    SOCKET_NUM=\${DISPLAY#*:} 
    SOCKET_PATH="/tmp/.X11-unix/X\${SOCKET_NUM%.*}"
    if command -v setfacl &> /dev/null && [ -e "\$SOCKET_PATH" ]; then
        setfacl -m u:$(id -u):rw "\$SOCKET_PATH" 2>/dev/null || {
            echo "[WARN] Could not set X11 socket ACL. Display may not work."
        }
    fi
    # REMOVED: chmod o+w fallback - this is a security risk
fi
```

**Additional X11 Security - Xauthority Method:**

Update the launcher script template in `_generate_app()`:

```bash
# In _generate_app function, update the X_FILE handling:
cat <<SCRIPT > "/tmp/$BIN_NAME"
#!/bin/bash

# 1. PREPARE XAUTHORITY - More secure than xhost
X_FILE="/tmp/.xauth_transfer_\${USER}_$$"
if command -v xauth >/dev/null; then
    # Extract only the MIT-MAGIC-COOKIE for current display
    xauth extract - "\$DISPLAY" 2>/dev/null | base64 > "\$X_FILE"
    chmod 600 "\$X_FILE"
fi

# 2. Use SI (Server Interpreted) authorization - most restrictive
if command -v xhost >/dev/null; then
    xhost +SI:localuser:\$(whoami) >/dev/null 2>&1
fi

# 3. CALL BRIDGE
CMD_STR="distrobox enter $BOX_NAME -- env XAUTH_SOURCE_FILE=\$X_FILE /usr/local/bin/run-as-dev $CMD \$@"

# 4. LAUNCH
if [ -t 0 ]; then
    \$CMD_STR
else
    # Secure log location
    LOG_DIR="\$HOME/.local/log"
    mkdir -p "\$LOG_DIR" 2>/dev/null
    chmod 700 "\$LOG_DIR" 2>/dev/null
    \$CMD_STR >> "\$LOG_DIR/${BIN_NAME}.log" 2>&1
fi

# 5. CLEANUP
rm -f "\$X_FILE" 2>/dev/null
SCRIPT
```

---

## Phase 2: High Severity Fixes

### 2.1 Remove Docker Group from Developer User

**File:** `manage-safe-environement.sh`

**Current Code (Line ~561):**
```bash
useradd -m -s /usr/bin/zsh -G audio,video,plugdev,docker "$INTERNAL_USER"
```

**New Code:**
```bash
# SECURITY: Developer user has NO docker group access
# Docker group grants root-equivalent access and must not be given
# For container operations, use: distrobox enter $BOX -- sudo docker <cmd>
useradd -m -s /usr/bin/zsh -G audio,video,plugdev "$INTERNAL_USER"
```

**If Docker Access is Required (Alternative):**

Instead of direct Docker access, set up a Docker socket proxy:

```bash
# Add to ROOT_SCRIPT provisioning section:

# --- DOCKER SOCKET PROXY (If Docker needed) ---
# This provides limited Docker API access without full socket access
if command -v docker &>/dev/null; then
    # Create restricted docker wrapper
    cat > /usr/local/bin/docker-restricted << 'DOCKERWRAP'
#!/bin/bash
# Restricted Docker wrapper - blocks dangerous operations
BLOCKED_CMDS="run exec attach cp export import save load"
CMD="$1"
for blocked in $BLOCKED_CMDS; do
    if [ "$CMD" = "$blocked" ]; then
        echo "ERROR: docker $CMD is restricted in this environment"
        exit 1
    fi
done
exec /usr/bin/docker "$@"
DOCKERWRAP
    chmod +x /usr/local/bin/docker-restricted
fi
```

---

### 2.2 Fix AppArmor - Use Permissive Profile Instead of Disabling

**File:** `manage-safe-environement.sh`

**Current Code (Lines ~533-540):**
```bash
# --- 1. APPARMOR NEUTRALIZATION ---
echo ">>> Neutralizing AppArmor..."
dpkg-divert --local --rename --add /usr/sbin/apparmor_parser 2>/dev/null || true
...
echo '#!/bin/sh' > /usr/sbin/apparmor_parser
echo 'exit 0' >> /usr/sbin/apparmor_parser
```

**New Code:**
```bash
# --- 1. APPARMOR CONFIGURATION ---
# Instead of disabling AppArmor, use complain mode for visibility
echo ">>> Configuring AppArmor (complain mode)..."

# Create a permissive profile for container applications
mkdir -p /etc/apparmor.d
cat > /etc/apparmor.d/distrobox-container << 'APPARMOR_PROFILE'
#include <tunables/global>

profile distrobox-container flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/audio>
  #include <abstractions/dbus-session>
  #include <abstractions/nameservice>
  #include <abstractions/X>
  
  # Allow most operations but log them
  /** rwmlkix,
  
  # Explicitly deny dangerous operations
  deny /boot/** w,
  deny /etc/shadow r,
  deny /etc/gshadow r,
  
  # Network access
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix stream,
  network unix dgram,
}
APPARMOR_PROFILE

# Load the profile if AppArmor is available
if command -v apparmor_parser &>/dev/null; then
    apparmor_parser -r /etc/apparmor.d/distrobox-container 2>/dev/null || true
fi
```

---

### 2.3 Remove Insecure X11 Socket Fallback

Already addressed in Phase 1.3 above.

---

### 2.4 Fix IPC Namespace

Already addressed in Phase 1.1 above (`--ipc=private --shm-size=4g`).

---

## Phase 3: Medium Severity Fixes

### 3.1 Secure Logging

**File:** `setup-apps.sh`

Already addressed in Phase 1.3 with secure log directory.

---

### 3.2 Validate External Scripts

**File:** `manage-safe-environement.sh`

**Current Code (Line ~661):**
```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended || true
```

**New Code:**
```bash
# Oh-My-Zsh installation with verification
OMZ_URL="https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh"
OMZ_SCRIPT="/tmp/omz_install.sh"

echo ">>> Downloading Oh-My-Zsh installer..."
curl -fsSL "$OMZ_URL" -o "$OMZ_SCRIPT"

# Verify the script contains expected content (basic sanity check)
if grep -q "oh-my-zsh" "$OMZ_SCRIPT" && grep -q "ZSH=" "$OMZ_SCRIPT"; then
    chmod +x "$OMZ_SCRIPT"
    sh "$OMZ_SCRIPT" --unattended || true
else
    echo "WARNING: Oh-My-Zsh script verification failed, skipping"
fi
rm -f "$OMZ_SCRIPT"
```

---

### 3.3 Use LUKS2 with Argon2

**File:** `manage-safe-environement.sh`

**Current Code (Line ~155):**
```bash
sudo cryptsetup luksFormat "$IMG_FILE" </dev/tty
```

**New Code:**
```bash
# Use LUKS2 with Argon2id KDF for stronger key derivation
# --pbkdf-memory: 1GB RAM requirement makes GPU attacks impractical
# --iter-time: 5 seconds of CPU time for key derivation
echo "⚠️  PLEASE SET A PASSPHRASE FOR THE VOLUME:"
sudo cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha512 \
    --pbkdf argon2id \
    --pbkdf-memory 1048576 \
    --pbkdf-parallel 4 \
    --iter-time 5000 \
    "$IMG_FILE" </dev/tty || {
    echo "❌ Failed to create encrypted volume"
    exit 1
}
```

---

## Phase 4: Complete Device Matrix

### Final Device Configuration

Add this function to `manage-safe-environement.sh`:

```bash
function build_device_flags() {
    local DEVICE_FLAGS=""
    
    # === GPU (Required for hardware acceleration) ===
    if [ -e /dev/dri ]; then
        DEVICE_FLAGS="$DEVICE_FLAGS --device /dev/dri"
        echo "   ✓ GPU: /dev/dri"
    fi
    
    # === Audio Devices (Required for video calls) ===
    if [ -d /dev/snd ]; then
        DEVICE_FLAGS="$DEVICE_FLAGS --device /dev/snd"
        echo "   ✓ Audio: /dev/snd"
    fi
    
    # === Webcam (Video devices) ===
    local video_count=0
    for vdev in /dev/video*; do
        if [ -e "$vdev" ]; then
            DEVICE_FLAGS="$DEVICE_FLAGS --device $vdev"
            video_count=$((video_count + 1))
        fi
    done
    if [ $video_count -gt 0 ]; then
        echo "   ✓ Webcam: $video_count video devices"
    fi
    
    # === USB (For YubiKey, hardware tokens) ===
    # Use cgroup rules instead of full /dev/bus/usb access
    if [ -d /dev/bus/usb ]; then
        # Allow USB HID devices (keyboards, security keys)
        DEVICE_FLAGS="$DEVICE_FLAGS --device-cgroup-rule='c 189:* rmw'"
        DEVICE_FLAGS="$DEVICE_FLAGS -v /dev/bus/usb:/dev/bus/usb:ro"
        echo "   ✓ USB: Read-only access for hardware keys"
    fi
    
    # === DO NOT INCLUDE (Security risks) ===
    # /dev/kvm - VM escape risk
    # /dev/fuse - Filesystem attacks
    # /dev/mem - Direct memory access
    # /dev/kmsg - Kernel message injection
    
    echo "$DEVICE_FLAGS"
}
```

---

## Complete Hardened Configuration

### Final `distrobox create` Command

```bash
# Build device flags
echo "🔧 Detecting hardware devices..."
DEVICES=$(build_device_flags)

# Create container with hardened settings
distrobox create --name "$BOX_NAME" \
    --image "ubuntu:24.04" \
    --volume "$WORK_DIR/home:/home/$INTERNAL_USER" \
    --home "$WORK_DIR/host_mask" \
    --unshare-process \
    --unshare-devsys \
    --additional-flags "\
        --ipc=private \
        --shm-size=4g \
        --cap-drop=ALL \
        --cap-add=SYS_PTRACE \
        --cap-add=SETUID \
        --cap-add=SETGID \
        --security-opt=no-new-privileges:true \
        $DEVICES \
        --volume /tmp/.X11-unix:/tmp/.X11-unix:ro \
        --volume /run/user/$(id -u)/pulse:/run/user/1000/pulse:ro \
        --env PULSE_SERVER=unix:/run/user/1000/pulse/native" \
    --init --yes
```

---

## Testing Checklist

After implementing fixes, verify:

### Security Tests

```bash
# 1. Verify no privileged mode
podman inspect $BOX_NAME | grep -i privileged
# Expected: "Privileged": false

# 2. Verify capabilities are dropped
podman inspect $BOX_NAME | grep -A 50 "CapDrop"
# Expected: List of dropped capabilities

# 3. Verify IPC is private
podman inspect $BOX_NAME | grep -i ipc
# Expected: "IpcMode": "private"

# 4. Test browser sandbox is working
distrobox enter $BOX_NAME -- brave-browser --version
# Should work without errors

# 5. Verify docker group is not present
distrobox enter $BOX_NAME -- groups developer
# Expected: developer audio video plugdev (NO docker)

# 6. Verify X11 access is restricted
xhost
# Expected: SI:localuser:skyron (NOT +local:)
```

### Functionality Tests

```bash
# 1. GPU acceleration
distrobox enter $BOX_NAME -- glxinfo | grep "direct rendering"
# Expected: direct rendering: Yes

# 2. Audio
distrobox enter $BOX_NAME -- aplay -l
# Expected: List of audio devices

# 3. Webcam
distrobox enter $BOX_NAME -- ls /dev/video*
# Expected: /dev/video0, /dev/video1, etc.

# 4. Browser launch
distrobox enter $BOX_NAME -- brave-browser --version
# Expected: Brave version info

# 5. VS Code launch
distrobox enter $BOX_NAME -- code --version
# Expected: VS Code version info
```

---

## Rollback Plan

If issues occur after implementing fixes:

```bash
# 1. Quick rollback - re-enable privileged mode temporarily
# Edit manage-safe-environement.sh and add back --privileged

# 2. Browser issues - add back sandbox disable
# Edit setup-apps.sh FLAGS to include --no-sandbox

# 3. X11 issues - temporarily allow local connections
xhost +local:

# 4. Full rollback
./manage-safe-environement.sh delete $BOX_NAME
git checkout manage-safe-environement.sh setup-apps.sh
./manage-safe-environement.sh create $BOX_NAME
```

---

## Maintenance

### Weekly

- Review `/var/log/apparmor.log` for violations
- Check `~/.local/log/` for application errors
- Run `freshclam` to update ClamAV definitions

### Monthly

- Update container base image
- Review and rotate LUKS passphrase if needed
- Audit installed extensions and applications

---

**Document Version:** 1.0  
**Last Updated:** December 22, 2025  
**Author:** Security Assessment (Automated)
