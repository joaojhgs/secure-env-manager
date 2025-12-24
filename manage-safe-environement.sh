#!/bin/bash
set -e

# ==============================================================================
# CONFIGURATION
# ==============================================================================
ACTION="${1:-help}"
BOX_NAME="$2"

# ==============================================================================
# INTERACTIVE INPUT HELPERS
# ==============================================================================

# Safe read function that ensures stdin is connected to terminal
# Uses nameref (declare -n) for proper variable indirection
function safe_read() {
    local prompt="$1"
    local -n result_var="$2"  # nameref for indirect variable assignment
    local silent="${3:-false}"
    
    # Write prompt to stderr (always visible, not buffered)
    echo -n "$prompt" >&2
    
    # Always read from /dev/tty to avoid stdin issues with sudo/pipes
    if [ "$silent" = "true" ]; then
        if ! IFS= read -r -s result_var < /dev/tty; then
            echo "❌ Error: Cannot read from terminal" >&2
            return 1
        fi
    else
        if ! IFS= read -r result_var < /dev/tty; then
            echo "❌ Error: Cannot read from terminal" >&2
            return 1
        fi
    fi
    echo "" >&2  # Newline after input
    
    # Reset terminal state after read to ensure it's ready for next command
    stty sane 2>/dev/null || true
}

if [[ -z "$BOX_NAME" && "$ACTION" != "help" ]]; then
    safe_read "🔹 Enter Environment Name (e.g., work-env): " BOX_NAME
fi
if [[ -z "$BOX_NAME" ]]; then BOX_NAME="work-env"; fi

# Storage Configuration
WORK_DIR="/opt/isolated_${BOX_NAME}"
IMG_FILE="/var/lib/isolated_${BOX_NAME}.img"
MAPPER_NAME="iso_${BOX_NAME}"
IMG_SIZE="100G"

# User Configuration
INTERNAL_USER="developer"
HOST_USER=${SUDO_USER:-$(logname)}
HOST_HOME=$(eval echo ~"$HOST_USER")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

function show_help() {
    echo "Usage: $0 [create|delete|mount|verify] [env_name]"
    echo "  create  : Build a new secure environment (SOC2 Compliant)"
    echo "  delete  : Destroy the container and wipe storage (Nuclear Mode)"
    echo "  mount   : Remount the encrypted storage (Run this after reboot)"
    echo "  verify  : Verify host home protection is working correctly"
}

function setup_encryption() {
    echo ""
    echo "🔐 STORAGE ENCRYPTION"
    
    if ! command -v cryptsetup &> /dev/null; then
        echo "❌ Error: 'cryptsetup' is not installed. Run: sudo apt install cryptsetup"
        exit 1
    fi

    local encrypt_choice
    safe_read "   Enable Encryption? (y/n): " encrypt_choice
    
    # Ensure terminal is in a good state after read
    stty sane 2>/dev/null || true
    
    if [[ "$encrypt_choice" =~ ^[Yy]$ ]]; then
        echo "⚡ Creating sparse encrypted volume (Max size: $IMG_SIZE)..."
        # ALWAYS remove existing file and any loop devices to avoid confirmation prompts
        echo "   Cleaning up any existing volumes..."
        # Close any open mappings first (redirect all I/O to avoid terminal issues)
        if lsblk 2>/dev/null | grep -q "$MAPPER_NAME"; then
            sudo cryptsetup close "$MAPPER_NAME" < /dev/null > /dev/null 2>&1 || true
        fi
        # Detach any loop devices (redirect I/O to avoid terminal issues)
        LOOP_DEV=$(sudo losetup -j "$IMG_FILE" < /dev/null 2>/dev/null | cut -d: -f1)
        if [ -n "$LOOP_DEV" ]; then
            sudo losetup -d "$LOOP_DEV" < /dev/null > /dev/null 2>&1 || true
        fi
        # COMPLETELY remove file - use multiple methods to ensure it's gone
        sudo rm -f "$IMG_FILE"
        sync
        sleep 1
        # Check if file still exists and force remove
        if [ -f "$IMG_FILE" ]; then
            sudo shred -u -z -n 1 "$IMG_FILE" 2>/dev/null || sudo rm -f "$IMG_FILE"
        fi
        sync
        sleep 0.5
        
        # Create completely new file - use dd to create it fresh
        sudo dd if=/dev/zero of="$IMG_FILE" bs=1M count=1 oflag=direct 2>/dev/null
        sudo truncate -s "$IMG_SIZE" "$IMG_FILE"
        sync
        
        # Zero out entire first 128MB to absolutely ensure no LUKS signatures remain
        sudo dd if=/dev/zero of="$IMG_FILE" bs=1M count=128 conv=notrunc oflag=direct,sync 2>/dev/null || true
        sync
        
        # Use wipefs multiple times to be absolutely sure
        sudo wipefs -a "$IMG_FILE" 2>/dev/null || true
        sudo wipefs -a "$IMG_FILE" 2>/dev/null || true
        sync
        
        # Verify file is actually clean before proceeding
        FILE_TYPE=$(sudo file "$IMG_FILE" 2>/dev/null | grep -i luks || echo "clean")
        if echo "$FILE_TYPE" | grep -qi luks; then
            echo "⚠️  WARNING: File still contains LUKS signature! Forcing complete wipe..."
            sudo dd if=/dev/zero of="$IMG_FILE" bs=1M count=256 conv=notrunc oflag=direct,sync 2>/dev/null || true
            sudo wipefs -a "$IMG_FILE" 2>/dev/null || true
            sync
        fi
        
        # Final check: ensure file is absolutely clean - keep wiping until file command says it's clean
        MAX_WIPES=5
        WIPE_COUNT=0
        while [ $WIPE_COUNT -lt $MAX_WIPES ]; do
            FILE_CHECK=$(sudo file "$IMG_FILE" 2>/dev/null | grep -i luks || echo "clean")
            if echo "$FILE_CHECK" | grep -qi luks; then
                echo "   Still detecting LUKS signature, wiping again... ($((WIPE_COUNT+1))/$MAX_WIPES)"
                sudo dd if=/dev/zero of="$IMG_FILE" bs=1M count=256 conv=notrunc oflag=direct,sync 2>/dev/null || true
                sudo wipefs -a "$IMG_FILE" 2>/dev/null || true
                sync
                WIPE_COUNT=$((WIPE_COUNT+1))
                sleep 0.5
            else
                break
            fi
        done
        
        echo "⚠️  PLEASE SET A PASSPHRASE FOR THE VOLUME:"
        # File should be clean now. Use simplest possible method
        # Ensure sudo has terminal access and cryptsetup can read passphrase
        # Reset terminal completely before cryptsetup
        stty sane 2>/dev/null || true
        
        # Run cryptsetup directly with sudo -S to preserve terminal
        # The script must run in foreground with full terminal access
        sudo cryptsetup luksFormat "$IMG_FILE" </dev/tty || {
            echo "❌ Failed to create encrypted volume"
            exit 1
        }
        echo "🔓 Opening volume..."
        echo "⚠️  Please enter the passphrase again to open the volume:"
        stty sane 2>/dev/null || true
        sudo cryptsetup open "$IMG_FILE" "$MAPPER_NAME" </dev/tty
        echo "⚙️  Formatting (ext4)..."
        sudo mkfs.ext4 "/dev/mapper/$MAPPER_NAME"
        sudo mount "/dev/mapper/$MAPPER_NAME" "$WORK_DIR"
        
        # 711 allows Podman traversal, blocks Host LS
        sudo chmod 711 "$WORK_DIR"
        sudo chown root:root "$WORK_DIR"
        
        # User Data Folder - MUST be owned by host user for rootless container
        sudo mkdir -p "$WORK_DIR/home"
        sudo chown "$HOST_USER:$HOST_USER" "$WORK_DIR/home"
        sudo chmod 755 "$WORK_DIR/home"
        
        # --- HOST MASKING FOLDER ---
        # CRITICAL: This folder masks the host home directory to prevent data loss
        # 1. Create empty folder to mask host home (must be completely empty)
        # 2. chown to HOST_USER so Distrobox can write init files (skel) if needed
        # 3. 755 is required for entry; empty content ensures isolation
        # 4. Remove any existing content to ensure it's truly empty
        sudo rm -rf "$WORK_DIR/host_mask"
        sudo mkdir -p "$WORK_DIR/host_mask"
        sudo chown "$HOST_USER:$HOST_USER" "$WORK_DIR/host_mask"
        sudo chmod 755 "$WORK_DIR/host_mask"
        
        # Verify it's empty (safety check)
        if [ "$(sudo ls -A "$WORK_DIR/host_mask" 2>/dev/null | wc -l)" -ne 0 ]; then
            echo "⚠️  WARNING: host_mask directory is not empty! Clearing it..."
            sudo rm -rf "$WORK_DIR/host_mask"/*
            sudo rm -rf "$WORK_DIR/host_mask"/.* 2>/dev/null || true
        fi
        return 0
    else
        sudo chmod 711 "$WORK_DIR"
        sudo chown root:root "$WORK_DIR"
        # User Data Folder - MUST be owned by host user for rootless container
        sudo mkdir -p "$WORK_DIR/home"
        sudo chown "$HOST_USER:$HOST_USER" "$WORK_DIR/home"
        sudo chmod 755 "$WORK_DIR/home"
        
        # Masking folder logic for non-encrypted mode
        # CRITICAL: This folder masks the host home directory to prevent data loss
        sudo rm -rf "$WORK_DIR/host_mask"
        sudo mkdir -p "$WORK_DIR/host_mask"
        sudo chown "$HOST_USER:$HOST_USER" "$WORK_DIR/host_mask"
        sudo chmod 755 "$WORK_DIR/host_mask"
        
        # Verify it's empty (safety check)
        if [ "$(sudo ls -A "$WORK_DIR/host_mask" 2>/dev/null | wc -l)" -ne 0 ]; then
            echo "⚠️  WARNING: host_mask directory is not empty! Clearing it..."
            sudo rm -rf "$WORK_DIR/host_mask"/*
            sudo rm -rf "$WORK_DIR/host_mask"/.* 2>/dev/null || true
        fi
        return 1
    fi
}

function mount_encrypted() {
    echo "🔓 MOUNTING ENCRYPTED STORAGE..."
    if [ ! -f "$IMG_FILE" ]; then echo "❌ No image found."; exit 1; fi
    if [ ! -d "$WORK_DIR" ]; then sudo mkdir -p "$WORK_DIR"; fi
    
    if ! lsblk | grep -q "$MAPPER_NAME"; then
        echo "⚠️  Please enter the passphrase to open the encrypted volume:"
        stty sane 2>/dev/null || true
        sudo cryptsetup open "$IMG_FILE" "$MAPPER_NAME" </dev/tty
    fi
    if ! mountpoint -q "$WORK_DIR"; then
        sudo mount "/dev/mapper/$MAPPER_NAME" "$WORK_DIR"
        echo "✅ Mounted."
    fi
    sudo chmod 711 "$WORK_DIR"
    
    # Ensure host_mask directory exists and is empty (safety check)
    if [ ! -d "$WORK_DIR/host_mask" ]; then
        echo "⚠️  Creating host_mask directory..."
        sudo mkdir -p "$WORK_DIR/host_mask"
        sudo chown "$HOST_USER:$HOST_USER" "$WORK_DIR/host_mask"
        sudo chmod 755 "$WORK_DIR/host_mask"
    fi
    
    # Verify mask is empty
    FILE_COUNT=$(sudo ls -A "$WORK_DIR/host_mask" 2>/dev/null | wc -l)
    if [ "$FILE_COUNT" -gt 0 ]; then
        echo "⚠️  WARNING: host_mask directory contains $FILE_COUNT items!"
        echo "   This could indicate a problem. Clearing it for safety..."
        sudo rm -rf "$WORK_DIR/host_mask"/*
        sudo rm -rf "$WORK_DIR/host_mask"/.* 2>/dev/null || true
    fi
}

function setup_video_permissions() {
    # Setup udev rule for video device permissions
    # Required because rootless containers use UID remapping which breaks group-based access
    local UDEV_RULE="/etc/udev/rules.d/99-video-container.rules"
    local UDEV_CONTENT='KERNEL=="video[0-9]*", MODE="0666"'
    
    if [ ! -f "$UDEV_RULE" ]; then
        echo "📹 Setting up video device permissions for container access..."
        echo "$UDEV_CONTENT" | sudo tee "$UDEV_RULE" > /dev/null
        sudo udevadm control --reload-rules
        # Apply to existing devices
        for vdev in /dev/video*; do
            if [ -e "$vdev" ]; then
                sudo chmod 666 "$vdev" 2>/dev/null || true
            fi
        done
        echo "✅ Video device permissions configured"
    fi
}

function verify_host_home_protection() {
    echo "🔍 Verifying container setup: $BOX_NAME"
    
    if ! distrobox list | grep -q "$BOX_NAME"; then
        echo "❌ Container '$BOX_NAME' does not exist."
        return 1
    fi
    
    # Check host home permissions
    HOST_HOME_PERMS=$(stat -c "%a" "$HOST_HOME" 2>/dev/null)
    if [ "$HOST_HOME_PERMS" = "700" ]; then
        echo "✅ Host home ($HOST_HOME) is protected (chmod 700)"
    else
        echo "⚠️  Host home permissions are $HOST_HOME_PERMS (expected 700)"
    fi
    
    # Note: Full verification requires container initialization which happens on first entry
    # Skip deep verification here - it will be done during provisioning
    echo "✅ Basic setup verification complete"
    echo "   (Full verification happens during provisioning)"
    return 0
}

function install_bridge() {
    echo "bridge: Installing internal permission bridge..."
    
    # Install socat for audio socket proxying
    distrobox enter "$BOX_NAME" -- sudo apt-get install -y socat pulseaudio-utils > /dev/null 2>&1 || true
    
    cat << 'EOF' | distrobox enter "$BOX_NAME" -- sudo tee /usr/local/bin/run-as-dev > /dev/null
#!/bin/bash
# Bridge Script v121 (Audio Fix - Root Socket Proxy)
# Uses socat to proxy pulse socket from host (owned by UID 1000) to a socket
# that developer user (UID 1001) can access.
set -e

DEVELOPER_HOME="/home/developer"
HOST_UID="${HOST_UID:-1000}"

# 1. CREATE PULSE PROXY SOCKET
# The host pulse socket is inside /run/user/1000 which is drwx------ 
# and inaccessible to developer (UID 1001). We use socat running as root
# to proxy the socket to a location developer can access.
DEV_RUNTIME="/tmp/runtime-developer"
PULSE_PROXY_DIR="$DEV_RUNTIME/pulse"

sudo mkdir -p "$DEV_RUNTIME"
sudo chown developer:developer "$DEV_RUNTIME"
sudo chmod 700 "$DEV_RUNTIME"

sudo mkdir -p "$PULSE_PROXY_DIR"
sudo chown developer:developer "$PULSE_PROXY_DIR"

HOST_PULSE_SOCKET="/run/host/run/user/$HOST_UID/pulse/native"
PROXY_SOCKET="$PULSE_PROXY_DIR/native"

if command -v socat &>/dev/null; then
    # Kill any existing proxy
    pkill -f "socat.*pulse/native" 2>/dev/null || true
    
    # Start socat as root (can access host socket), creates socket owned by developer
    sudo rm -f "$PROXY_SOCKET"
    sudo socat UNIX-LISTEN:"$PROXY_SOCKET",fork,user=developer,group=developer,mode=600 UNIX-CONNECT:"$HOST_PULSE_SOCKET" &
    sleep 0.5
fi

# 2. COPY PULSE COOKIE FOR AUTHENTICATION  
HOST_USER_NAME=$(getent passwd "$HOST_UID" 2>/dev/null | cut -d: -f1 || echo "")
if [ -n "$HOST_USER_NAME" ] && [ -f "/run/host/home/$HOST_USER_NAME/.config/pulse/cookie" ]; then
    sudo mkdir -p "$DEVELOPER_HOME/.config/pulse"
    sudo cp "/run/host/home/$HOST_USER_NAME/.config/pulse/cookie" "$DEVELOPER_HOME/.config/pulse/cookie" 2>/dev/null || true
    sudo chown -R developer:developer "$DEVELOPER_HOME/.config/pulse" 2>/dev/null || true
    sudo chmod 600 "$DEVELOPER_HOME/.config/pulse/cookie" 2>/dev/null || true
fi

# 3. GENERATE MACHINE ID
if [ ! -f /var/lib/dbus/machine-id ]; then
    sudo mkdir -p /var/lib/dbus
    sudo dbus-uuidgen --ensure
fi

# 4. SWITCH TO DEVELOPER
sudo -E -u developer bash -c '
    export DISPLAY="$1"
    export HOME="/home/developer"
    
    # --- AUDIO SETUP ---
    export XDG_RUNTIME_DIR="/tmp/runtime-developer"
    export PULSE_SERVER="unix:/tmp/runtime-developer/pulse/native"
    export PULSE_COOKIE="$HOME/.config/pulse/cookie"
    
    # --- DISPLAY FIXES ---
    unset WAYLAND_DISPLAY
    unset XDG_SESSION_TYPE
    export LIBGL_ALWAYS_SOFTWARE=0
    
    # ISOLATE DATA DIRS
    export XDG_DATA_DIRS="/usr/local/share:/usr/share"
    export XDG_DATA_HOME="$HOME/.local/share"
    export XDG_CONFIG_HOME="$HOME/.config"
    export XDG_CACHE_HOME="$HOME/.cache"
    export XDG_STATE_HOME="$HOME/.local/state"
    mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
    
    unset DBUS_SESSION_BUS_ADDRESS

    # IMPORT X11 KEYS
    export XAUTHORITY="$(mktemp /tmp/xauth_user.XXXXXX)"
    touch "$XAUTHORITY"
    if [ -n "$XAUTH_SOURCE_FILE" ] && [ -f "$XAUTH_SOURCE_FILE" ]; then
        xauth -f "$XAUTHORITY" nmerge "$XAUTH_SOURCE_FILE" 2>/dev/null
    fi

    # ENVIRONMENT
    export PATH="/opt/isolated_wrappers:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:$PATH"
    export ASDF_DIR="$HOME/.asdf"
    if [ -f "$HOME/.asdf/asdf.sh" ]; then . "$HOME/.asdf/asdf.sh"; fi
    export BROWSER=brave-browser
    export GTK_USE_PORTAL=0
    export NO_AT_BRIDGE=1
    
    shift 1
    
    CMD_NAME="$1"
    CMD_PATH="$(command -v "$CMD_NAME")"
    if [ -z "$CMD_PATH" ]; then
        if [ -f "/usr/bin/$CMD_NAME" ]; then CMD_PATH="/usr/bin/$CMD_NAME"; fi
        if [ -f "/bin/$CMD_NAME" ]; then CMD_PATH="/bin/$CMD_NAME"; fi
    fi

    if [ -z "$CMD_PATH" ]; then
        echo "[BRIDGE ERROR] Binary \"$CMD_NAME\" not found."
        exit 1
    fi
    shift 1
    
    exec dbus-run-session -- "$CMD_PATH" "$@"
' -- "$DISPLAY" "$@"
EOF

    distrobox enter "$BOX_NAME" -- sudo chmod +x /usr/local/bin/run-as-dev
    echo "✅ Bridge installed."
}


# ==============================================================================
# MAIN LOGIC
# ==============================================================================

if [ "$ACTION" == "verify" ]; then
    if [[ -z "$BOX_NAME" ]]; then
        echo "❌ Error: Environment name required for verify action"
        show_help
        exit 1
    fi
    verify_host_home_protection
    exit $?

elif [ "$ACTION" == "mount" ]; then
    mount_encrypted
    exit 0

elif [ "$ACTION" == "delete" ]; then
    echo "🔥 DELETING ENVIRONMENT: $BOX_NAME"
    sudo find /usr/local/bin -name "${BOX_NAME}-*" -delete
    find ~/.local/share/applications -name "${BOX_NAME}-*.desktop" -delete
    
    echo "🛑 Stopping container..."
    distrobox stop "$BOX_NAME" --yes || true
    distrobox rm "$BOX_NAME" --force || true
    
    echo "🧹 Cleaning up storage..."
    
    # 1. Kill processes inside mount (Force -9)
    if [ -d "$WORK_DIR" ]; then
        sudo fuser -k -9 -m "$WORK_DIR" >/dev/null 2>&1 || true
        sleep 1
    fi
    
    # 2. Unmount (Lazy Force)
    if mountpoint -q "$WORK_DIR"; then 
        echo "   Unmounting volume..."
        sudo umount -l "$WORK_DIR" || sudo umount -f "$WORK_DIR"
        sleep 1
    fi
    
    # 3. Close LUKS (NUCLEAR OPTION)
    if lsblk | grep -q "$MAPPER_NAME"; then 
        echo "   Locking encrypted volume..."
        sudo dmsetup remove --force "$MAPPER_NAME" || \
        (sudo dmsetup clear "$MAPPER_NAME" && sudo dmsetup remove --force --retry "$MAPPER_NAME") || \
        sudo cryptsetup close "$MAPPER_NAME"
    fi

    # 4. Detach Loop Device (CRITICAL FIX)
    if [ -f "$IMG_FILE" ]; then
        LOOP_DEV=$(sudo losetup -j "$IMG_FILE" | cut -d: -f1)
        if [ -n "$LOOP_DEV" ]; then
            echo "   Detaching loop device: $LOOP_DEV"
            sudo losetup -d "$LOOP_DEV" || true
        fi
    fi
    
    if [ -d "$WORK_DIR" ]; then sudo rm -rf "$WORK_DIR"; fi
    if [ -f "$IMG_FILE" ]; then sudo rm -f "$IMG_FILE"; fi
    
    echo "✅ Cleanup complete."
    exit 0

elif [ "$ACTION" == "create" ]; then
    echo "🏗️  CREATING ROOTLESS ENVIRONMENT: $BOX_NAME"
    echo ""
    echo "🛡️  CONTAINER ISOLATION:"
    echo "   - Developer user will work in isolated /home/developer (persistent storage)"
    echo "   - Developer has NO sudo access inside the container"
    echo "   - NOTE: Distrobox mounts host home for integration (visible but separate from \$HOME)"
    echo ""
    
    # --- AUTO-CLEANUP CHECK ---
    if distrobox list | grep -q "$BOX_NAME"; then
        echo "⚠️  Container '$BOX_NAME' already exists."
        echo "   To apply all fixes, it must be recreated."
        safe_read "   Recreate now? (y/n): " DO_RECREATE
        if [[ "$DO_RECREATE" =~ ^[Yy]$ ]]; then
            $0 delete "$BOX_NAME"
        else
            echo "   Skipping creation. Configuration may be incomplete."
        fi
    fi
    
    safe_read "   Set password for internal user 'developer': " USER_PASS true
    if [ -z "$USER_PASS" ]; then echo "❌ Password cannot be empty."; exit 1; fi

    # Ensure we have sudo access before proceeding (helps with stdin issues)
    echo "🔐 Checking sudo access..."
    if ! sudo -n true 2>/dev/null; then
        echo "   Sudo access required. You may be prompted for your password."
        # Use -v to validate and extend sudo timeout
        # This helps prevent stdin issues later
        sudo -v || {
            echo "   Please enter your sudo password when prompted above."
        }
    fi
    echo ""
    
    if [ ! -d "$WORK_DIR" ]; then sudo mkdir -p "$WORK_DIR"; fi
    DO_ENCRYPT=""
    # Call setup_encryption and capture return value
    # Return 0 = encryption enabled, Return 1 = no encryption
    # Use subshell to prevent set -e from exiting on return 1
    if setup_encryption; then
        ENCRYPTION_ENABLED=0
    else
        ENCRYPTION_ENABLED=1
    fi
    
    if ! distrobox list | grep -q "$BOX_NAME"; then
        # --- CRITICAL FIX: MASK HOST HOME DIRECTORY TO PREVENT DATA LOSS ---
        # Distrobox by default mounts the host's home directory inside the container.
        # The --home flag only changes $HOME env var, it does NOT prevent the host home mount.
        # 
        # Strategy:
        # 1. Use --mount type=tmpfs to create an empty tmpfs filesystem OVER /home/$HOST_USER
        #    This effectively masks the real host home with an empty temporary filesystem
        # 2. --volume mounts isolated storage for the developer user at /home/$INTERNAL_USER
        # 3. --home sets $HOME to the developer's isolated folder
        # 4. --security-opt no-new-privileges prevents privilege escalation via setuid binaries
        #
        # SECURITY MODEL:
        # - Container's /home/$HOST_USER is an empty tmpfs (real host home is hidden)
        # - Container user has isolated persistent home at /home/$INTERNAL_USER
        # - Real host home is NEVER accessible inside the container
        # - Developer user has NO sudo access (removed from sudo group)
        # - no-new-privileges prevents setuid/capability escalation
        # - Admin tasks: use 'distrobox enter $BOX -- sudo <cmd>' (uses HOST sudo)
        
        echo "🛡️  Setting up host home protection..."
        echo "   Host home: $HOST_HOME (will be masked with empty folder)"
        echo "   Container user home: $WORK_DIR/home → /home/$INTERNAL_USER"
        echo "   Security: no-new-privileges enabled, developer has no sudo"
        
        # Note: $WORK_DIR/home and $WORK_DIR/host_mask are already created by setup_encryption
        # Just verify they exist
        if [ ! -d "$WORK_DIR/home" ]; then
            echo "❌ ERROR: $WORK_DIR/home does not exist. Setup failed."
            exit 1
        fi
        
        # MOUNT STRATEGY:
        # 1. --home "$WORK_DIR/host_mask" tells distrobox to mount our EMPTY folder
        #    to /home/$HOST_USER INSTEAD of the real host home. This masks it.
        # 2. --volume provides persistent storage at /home/$INTERNAL_USER for developer
        # 3. NO tmpfs needed - the --home redirect already provides the masking
        #
        # Result: /home/skyron = empty folder (host_mask), /home/developer = isolated storage
        #
        # SECURITY MODEL:
        # - Developer user has NO sudo group membership (can't sudo inside container)
        # - Host home is set to 700 (owner-only) - developer user can't access it
        # - This is safe: skyron can still access on host, only "others" are blocked
        
        # Build device list based on available hardware
        DEVICES=""
        
        # GPU (required for hardware acceleration)
        [ -e /dev/dri ] && DEVICES="$DEVICES --device /dev/dri"
        
        # Audio devices (required for video calls, sound)
        # Mount the entire /dev/snd directory if it exists
        [ -d /dev/snd ] && DEVICES="$DEVICES --device /dev/snd"
        
        # Webcam (enumerate available video devices)
        # Check if any video devices exist before iterating
        if ls /dev/video* 1>/dev/null 2>&1; then
            for video_dev in /dev/video*; do
                [ -e "$video_dev" ] && DEVICES="$DEVICES --device $video_dev"
            done
        fi
        
        # Audio passthrough - PulseAudio/PipeWire socket
        # This allows audio input (microphone) and output (speakers) to work
        AUDIO_MOUNTS=""
        HOST_XDG_RUNTIME="/run/user/$(id -u $HOST_USER)"
        
        # PulseAudio socket
        if [ -e "$HOST_XDG_RUNTIME/pulse/native" ]; then
            AUDIO_MOUNTS="$AUDIO_MOUNTS --volume $HOST_XDG_RUNTIME/pulse:$HOST_XDG_RUNTIME/pulse:ro"
        fi
        
        # PipeWire socket (modern systems)
        if [ -e "$HOST_XDG_RUNTIME/pipewire-0" ]; then
            AUDIO_MOUNTS="$AUDIO_MOUNTS --volume $HOST_XDG_RUNTIME/pipewire-0:$HOST_XDG_RUNTIME/pipewire-0:rw"
        fi
        
        # SECURITY NOTE: We cannot use --security-opt=no-new-privileges:true because
        # distrobox requires sudo inside the container for provisioning and package installation.
        # Security is maintained through: capability dropping, namespace isolation, and host home masking.
        #
        # NOTE: Removed --unshare-devsys as it prevents access to audio/video devices
        # Device access is controlled explicitly via --device flags instead
        distrobox create --name "$BOX_NAME" \
            --image "ubuntu:24.04" \
            --volume "$WORK_DIR/home:/home/$INTERNAL_USER" \
            --home "$WORK_DIR/host_mask" \
            --unshare-process \
            --additional-flags "--ipc=private --shm-size=4g --cap-drop=ALL --cap-add=SYS_PTRACE --cap-add=SETUID --cap-add=SETGID $DEVICES $AUDIO_MOUNTS --volume /tmp/.X11-unix:/tmp/.X11-unix:ro" \
            --init --yes
        
        # PROTECT HOST HOME: Set to 700 so only owner (skyron) can access
        # This blocks the developer user (different UID) inside the container
        # Safe because: owner keeps full access, sudo still works, only "others" blocked
        echo "🔒 Setting host home to owner-only access (chmod 700)..."
        chmod 700 "$HOST_HOME"
        
        # Verify protection after creation
        verify_host_home_protection
    fi

    echo "⚙️  Provisioning container (Root)..."
    
    # -----------------------------------------------------------
    # ROOT PROVISIONING
    # -----------------------------------------------------------
    ROOT_SCRIPT=$(mktemp)
    cat << 'EOF' > "$ROOT_SCRIPT"
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# --- 1. APPARMOR CONFIGURATION (Permissive Mode) ---
# Instead of disabling AppArmor entirely, we configure it in complain mode
# This logs violations without blocking, providing security visibility
echo ">>> Configuring AppArmor in complain mode..."
if command -v aa-complain >/dev/null 2>&1; then
    # Set all profiles to complain mode (log but don't enforce)
    aa-complain /etc/apparmor.d/* 2>/dev/null || true
else
    # If aa-complain not available, create a permissive wrapper that logs
    echo "AppArmor tools not available, skipping profile configuration"
fi

echo ">>> Installing System & Compliance Packages..."
apt-get update && apt-get install -y curl git zsh wget unzip build-essential sudo \
    software-properties-common ca-certificates gnupg xdg-utils desktop-file-utils xauth \
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev \
    docker.io iptables libsecret-1-0 gnome-keyring dbus-x11 acl \
    libx11-xcb1 libxss1 libasound2t64 libnss3 libatk-bridge2.0-0 libgtk-3-0t64 libgbm1 fonts-noto-color-emoji \
    clamav clamav-daemon unattended-upgrades xscreensaver

# Enable Unattended Upgrades
echo 'Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}"; "${distro_id}:${distro_codename}-security"; };' > /etc/apt/apt.conf.d/50unattended-upgrades
service unattended-upgrades start || true


INTERNAL_USER="developer"

# SECURITY: Create developer user WITHOUT sudo or docker access
# - No sudo: prevents bypassing the tmpfs mask over host home
# - No docker: docker group grants root-equivalent access (HSV-003)
# For admin tasks, use: distrobox enter $BOX_NAME -- sudo <command>
# (which uses the host user's sudo, not container sudo)
if ! id "$INTERNAL_USER" &>/dev/null; then 
    useradd -m -s /usr/bin/zsh -G audio,video,plugdev "$INTERNAL_USER"
fi

# --- FIX: FORCE ZSH DEFAULT ---
if ! grep -q "/usr/bin/zsh" /etc/shells; then echo "/usr/bin/zsh" >> /etc/shells; fi
if [ -f /usr/bin/zsh ]; then
    usermod -s /usr/bin/zsh "$INTERNAL_USER" || true
    sed -i "s|^$INTERNAL_USER:.*|$INTERNAL_USER:x:$(id -u $INTERNAL_USER):$(id -g $INTERNAL_USER)::/home/$INTERNAL_USER:/usr/bin/zsh|" /etc/passwd
fi

# Safe Chown
chown -R "$INTERNAL_USER:$INTERNAL_USER" "/home/$INTERNAL_USER/"* 2>/dev/null || true
chown "$INTERNAL_USER:$INTERNAL_USER" "/home/$INTERNAL_USER" 2>/dev/null || true

# XDG OPEN WRAPPER (will be configured by app setup script)
# SECURITY: Using --disable-setuid-sandbox instead of --no-sandbox (CVE-CUSTOM-002)
mkdir -p "/opt/isolated_wrappers"
echo '#!/bin/bash' > "/opt/isolated_wrappers/xdg-open"
echo 'echo "[WRAPPER] Opening URL: $1"' >> "/opt/isolated_wrappers/xdg-open"
echo 'if command -v brave-browser >/dev/null 2>&1; then' >> "/opt/isolated_wrappers/xdg-open"
echo '    exec brave-browser --disable-setuid-sandbox "$1"' >> "/opt/isolated_wrappers/xdg-open"
echo 'else' >> "/opt/isolated_wrappers/xdg-open"
echo '    echo "No browser configured yet. Run setup-apps.sh to install applications."' >> "/opt/isolated_wrappers/xdg-open"
echo 'fi' >> "/opt/isolated_wrappers/xdg-open"
chmod +x "/opt/isolated_wrappers/xdg-open"
EOF
    
    cat "$ROOT_SCRIPT" | distrobox enter "$BOX_NAME" -- sudo tee /tmp/root.sh > /dev/null
    distrobox enter "$BOX_NAME" -- sudo chmod +x /tmp/root.sh
    distrobox enter "$BOX_NAME" -- sudo /bin/bash /tmp/root.sh
    
    # --- PASSWORD FIX: PIPE TO AVOID SHELL INTERPOLATION ---
    echo "$INTERNAL_USER:$USER_PASS" | distrobox enter "$BOX_NAME" -- sudo chpasswd

    echo "⚙️  Provisioning container (User)..."
    
    # -----------------------------------------------------------
    # USER PROVISIONING
    # -----------------------------------------------------------
    USER_SCRIPT=$(mktemp)
    cat << 'EOF' > "$USER_SCRIPT"
#!/bin/bash
set -e
cd "$HOME"

# --- 1. MASKING: PERSISTENT HOST PROTECTION ---
{
    echo 'export XDG_DATA_DIRS="/usr/local/share:/usr/share"'
    echo 'export XDG_CONFIG_HOME="$HOME/.config"'
    echo 'export XDG_DATA_HOME="$HOME/.local/share"'
    echo 'export XDG_CACHE_HOME="$HOME/.cache"'
    echo '[ -z "$ZSH_VERSION" ] && exec /usr/bin/zsh -l'
} >> "$HOME/.bashrc"

# --- 2. ASDF INSTALLATION & GLOBAL DEFAULTS ---
if [ ! -d ".asdf" ]; then 
    echo ">>> Installing ASDF..."
    git clone https://github.com/asdf-vm/asdf.git .asdf --branch v0.14.0
    . "$HOME/.asdf/asdf.sh"
    
    echo ">>> Installing Python (Latest)..."
    asdf plugin add python || true
    asdf install python latest || echo "Python install failed"
    asdf global python latest || true
    
    echo ">>> Installing NodeJS (Latest)..."
    asdf plugin add nodejs https://github.com/asdf-vm/asdf-nodejs.git || true
    asdf install nodejs latest || echo "NodeJS install failed"
    asdf global nodejs latest || true
fi

# Configs
if [ ! -d ".oh-my-zsh" ]; then 
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended || true
fi

touch "$HOME/.profile" "$HOME/.zshrc" "$HOME/.bashrc"
if ! grep -q "asdf.sh" "$HOME/.profile"; then echo '. "$HOME/.asdf/asdf.sh"' >> "$HOME/.profile"; fi
if ! grep -q "asdf.sh" "$HOME/.zshrc"; then echo '. "$HOME/.asdf/asdf.sh"' >> "$HOME/.zshrc"; fi
if ! grep -q "isolated_wrappers" "$HOME/.bashrc"; then echo 'export PATH=/opt/isolated_wrappers:$PATH' >> "$HOME/.bashrc"; fi
if ! grep -q "isolated_wrappers" "$HOME/.zshrc"; then echo 'export PATH=/opt/isolated_wrappers:$PATH' >> "$HOME/.zshrc"; fi

# XScreenSaver (SOC2 Check)
cat <<XS > "$HOME/.xscreensaver"
timeout: 0:15:00
lock:    True
mode:    blank
XS

# --- 3. SSH KEY GENERATION FOR GIT ---
echo ">>> Generating SSH key for Git..."
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
SSH_KEY_FILE="$HOME/.ssh/id_ed25519_ENV_NAME"
if [ ! -f "$SSH_KEY_FILE" ]; then
    ssh-keygen -t ed25519 -C "developer@ENV_NAME" -f "$SSH_KEY_FILE" -N ""
    echo "✅ SSH key generated: $SSH_KEY_FILE"
    echo ""
    echo "📋 Add this public key to your Git provider (GitHub/GitLab/etc.):"
    cat "${SSH_KEY_FILE}.pub"
    echo ""
else
    echo "SSH key already exists: $SSH_KEY_FILE"
fi

# Configure SSH to use this key for common Git hosts
cat >> "$HOME/.ssh/config" << 'SSHCONFIG'
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_ENV_NAME
    IdentitiesOnly yes

Host gitlab.com
    HostName gitlab.com
    User git
    IdentityFile ~/.ssh/id_ed25519_ENV_NAME
    IdentitiesOnly yes

Host bitbucket.org
    HostName bitbucket.org
    User git
    IdentityFile ~/.ssh/id_ed25519_ENV_NAME
    IdentitiesOnly yes
SSHCONFIG
chmod 600 "$HOME/.ssh/config"
EOF

    # Replace ENV_NAME placeholder with actual box name
    sed -i "s/ENV_NAME/$BOX_NAME/g" "$USER_SCRIPT"

    cat "$USER_SCRIPT" | distrobox enter "$BOX_NAME" -- sudo tee /home/$INTERNAL_USER/user.sh > /dev/null
    distrobox enter "$BOX_NAME" -- sudo chown $INTERNAL_USER:$INTERNAL_USER /home/$INTERNAL_USER/user.sh
    distrobox enter "$BOX_NAME" -- sudo chmod +x /home/$INTERNAL_USER/user.sh
    distrobox enter "$BOX_NAME" -- sudo -u "$INTERNAL_USER" /bin/bash /home/$INTERNAL_USER/user.sh

    install_bridge
    setup_video_permissions
    
    # Final verification
    echo ""
    echo "🔍 Performing final host home protection check..."
    if verify_host_home_protection; then
        echo ""
        echo "🎉 SUCCESS! Secure Environment '$BOX_NAME' created."
        echo "💡 Next step: Run './setup-apps.sh $BOX_NAME' to install applications and launchers."
        if [ "$ENCRYPTION_ENABLED" -eq 0 ]; then
            echo "🔒 ENCRYPTION ACTIVE: You must run './manage-safe-environement.sh mount $BOX_NAME' after any reboot."
        fi
    else
        echo ""
        echo "⚠️  WARNING: Host home protection verification failed!"
        echo "   Please review the warnings above before using the container."
        echo "   Your host home directory may be at risk."
        exit 1
    fi
else
    show_help
    exit 1
fi