#!/bin/bash
set -e

# ==============================================================================
# CONFIGURATION
# ==============================================================================
BOX_NAME="$1"

if [[ -z "$BOX_NAME" ]]; then
    read -p "🔹 Enter Environment Name (e.g., work): " BOX_NAME < /dev/tty
fi

if [[ -z "$BOX_NAME" ]]; then
    echo "❌ Error: Environment name is required."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTERNAL_USER="developer"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

function show_help() {
    echo "Usage: $0 [env_name]"
    echo "  Installs applications (VS Code, Brave, Chrome, Cursor) and extensions"
    echo "  Creates launchers and MIME type mappings for the specified environment"
}

function check_container() {
    if ! distrobox list | grep -q "$BOX_NAME"; then
        echo "❌ Error: Container '$BOX_NAME' does not exist."
        echo "   Please create it first using: ./manage-safe-environement.sh create $BOX_NAME"
        exit 1
    fi
}

function create_launchers() {
    echo "🚀 Generating launchers..."
    
    _generate_app() {
        local APP_NAME="$1"
        local CMD="$2"
        local ICON="$3"
        local BIN_NAME="${BOX_NAME}-$(echo "$APP_NAME" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')"
        
        cat <<SCRIPT > "/tmp/$BIN_NAME"
#!/bin/bash

# 1. PREPARE KEY
X_FILE="/tmp/.xauth_transfer_\${USER}"
if command -v xauth >/dev/null; then
    xauth nlist \$DISPLAY | sed -e 's/^..../ffff/' > "\$X_FILE"
    chmod 644 "\$X_FILE"
fi

# 2. CALL BRIDGE
CMD_STR="distrobox enter $BOX_NAME -- env XAUTH_SOURCE_FILE=\$X_FILE /usr/local/bin/run-as-dev $CMD \$@"

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

# 3. LAUNCH
if [ -t 0 ]; then
    \$CMD_STR
else
    \$CMD_STR >> /tmp/${BIN_NAME}.log 2>&1
fi
SCRIPT
        sudo mv "/tmp/$BIN_NAME" "/usr/local/bin/$BIN_NAME"
        sudo chmod +x "/usr/local/bin/$BIN_NAME"

        mkdir -p ~/.local/share/applications
        cat <<DESKTOP > ~/.local/share/applications/$BIN_NAME.desktop
[Desktop Entry]
Name=$APP_NAME - $BOX_NAME
Exec=/usr/local/bin/$BIN_NAME %U
Type=Application
Icon=$ICON
Terminal=false
Categories=Development;
StartupNotify=true
DESKTOP
    }

    # FLAGS
    FLAGS="--password-store=basic --no-sandbox --disable-dev-shm-usage --disable-gpu-sandbox --ozone-platform=x11 --verbose"
    
    # Only create launchers for installed apps
    if distrobox enter "$BOX_NAME" -- command -v code >/dev/null 2>&1; then
        _generate_app "VSCode" "code --wait $FLAGS" "com.visualstudio.code"
    fi
    
    if distrobox enter "$BOX_NAME" -- command -v cursor >/dev/null 2>&1; then
        _generate_app "Cursor" "cursor --wait $FLAGS" "cursor"
    fi
    
    if distrobox enter "$BOX_NAME" -- command -v brave-browser >/dev/null 2>&1; then
        _generate_app "Brave" "brave-browser $FLAGS" "brave-browser"
    fi
    
    if distrobox enter "$BOX_NAME" -- command -v google-chrome >/dev/null 2>&1; then
        _generate_app "Chrome" "google-chrome $FLAGS" "google-chrome"
    fi
    
    if distrobox enter "$BOX_NAME" -- command -v antigravity >/dev/null 2>&1; then
        _generate_app "Antigravity" "antigravity" "antigravity"
    fi
    
    _generate_app "Terminal" "zsh" "utilities-terminal"
    
    # DRATA LAUNCHER CHECK
    if distrobox enter "$BOX_NAME" -- command -v drata-agent >/dev/null 2>&1; then
         _generate_app "Drata" "drata-agent $FLAGS" "drata-agent"
    fi
    
    echo "✅ Launchers created."
}

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

if [ "$BOX_NAME" == "help" ] || [ "$BOX_NAME" == "-h" ] || [ "$BOX_NAME" == "--help" ]; then
    show_help
    exit 0
fi

check_container

echo "📦 INSTALLING APPLICATIONS FOR: $BOX_NAME"

# -----------------------------------------------------------
# ROOT PROVISIONING: APPS
# -----------------------------------------------------------
ROOT_SCRIPT=$(mktemp)
cat << 'EOF' > "$ROOT_SCRIPT"
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

echo ">>> Installing Applications..."

# VS Code
if ! command -v code &> /dev/null; then
    echo "   Installing VS Code..."
    mkdir -p /etc/apt/keyrings
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/apt/keyrings/packages.microsoft.gpg > /dev/null
    chmod 644 /etc/apt/keyrings/packages.microsoft.gpg
    echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list
    apt-get update && apt-get install -y code
fi

# Brave
if ! command -v brave-browser &> /dev/null; then 
    echo "   Installing Brave Browser..."
    curl -fsS https://dl.brave.com/install.sh | sh
fi

# Chrome
if ! command -v google-chrome &> /dev/null; then 
    echo "   Installing Google Chrome..."
    wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    apt-get install -y /tmp/chrome.deb || apt-get install -f -y
    rm -f /tmp/chrome.deb
fi

# Cursor
if ! command -v cursor &> /dev/null; then
    echo "   Installing Cursor..."
    wget -O /tmp/cursor.deb "https://api2.cursor.sh/updates/download/golden/linux-x64-deb/cursor/"
    apt-get install -y /tmp/cursor.deb || apt-get install -f -y
    rm -f /tmp/cursor.deb
fi

# BRAVE POLICIES & EXTENSIONS
echo ">>> Configuring Brave Policies..."
mkdir -p "/etc/brave/policies/managed" "/etc/opt/chrome/policies/managed"
E_JSON='{ "ExtensionInstallForcelist": [ "cjpalhdlnbpafiamejdnhcphjbkeiagm", "nngceckbapebfimnlniiiahkandclblb", "fmpjacodnojmnejpqbewdnoipchhanaa", "fmkadmapgofadopljbjfkapdkoienihi" ] }'
echo "$E_JSON" > "/etc/brave/policies/managed/extensions.json"
echo "$E_JSON" > "/etc/opt/chrome/policies/managed/extensions.json"
chmod -R 755 "/etc/brave" "/etc/opt/chrome"

# Update XDG OPEN WRAPPER to use Brave
if [ -f "/opt/isolated_wrappers/xdg-open" ]; then
    cat > "/opt/isolated_wrappers/xdg-open" << 'XDGEOF'
#!/bin/bash
echo "[WRAPPER] Opening URL: $1"
if command -v brave-browser >/dev/null 2>&1; then
    exec brave-browser --no-sandbox "$1"
else
    echo "No browser available"
    exit 1
fi
XDGEOF
    chmod +x "/opt/isolated_wrappers/xdg-open"
fi
EOF

cat "$ROOT_SCRIPT" | distrobox enter "$BOX_NAME" -- sudo tee /tmp/root-apps.sh > /dev/null
distrobox enter "$BOX_NAME" -- sudo chmod +x /tmp/root-apps.sh
distrobox enter "$BOX_NAME" -- sudo /bin/bash /tmp/root-apps.sh

# -----------------------------------------------------------
# DRATA INSTALLATION
# -----------------------------------------------------------
DRATA_DEB=$(find "$SCRIPT_DIR" -maxdepth 1 -name "Drata*.deb" | head -n 1)
if [ -n "$DRATA_DEB" ]; then
    echo "📦 Found Drata Agent: $(basename "$DRATA_DEB")"
    cat "$DRATA_DEB" | distrobox enter "$BOX_NAME" -- sudo tee /tmp/drata.deb > /dev/null
    # Drata's post-install script tries to load AppArmor profile which fails in containers
    # Use dpkg with --force-confdef to install, ignoring post-install script failures
    distrobox enter "$BOX_NAME" -- sudo dpkg -i --force-confdef /tmp/drata.deb 2>/dev/null || true
    distrobox enter "$BOX_NAME" -- sudo apt-get install -f -y 2>/dev/null || true
    # Check if binary was installed despite post-install failure
    if distrobox enter "$BOX_NAME" -- command -v drata-agent >/dev/null 2>&1; then
        echo "✅ Drata Agent Installed (AppArmor profile skipped - normal in containers)."
    else
        echo "⚠️  Drata Agent installation may have issues. Check manually."
    fi
else
    echo "⚠️  No Drata Agent .deb found in $SCRIPT_DIR. Skipping."
fi

# -----------------------------------------------------------
# USER PROVISIONING: EXTENSIONS & MIME TYPES
# -----------------------------------------------------------
echo "⚙️  Installing User Extensions and Configurations..."

USER_SCRIPT=$(mktemp)
cat << 'EOF' > "$USER_SCRIPT"
#!/bin/bash
set -e
cd "$HOME"

# --- 1. VS CODE EXTENSIONS (Prioritized & POSIX Safe) ---
# Using string list loop to prevent "Syntax error: ( unexpected" on Dash/Sh.
if command -v code >/dev/null 2>&1; then
    echo ">>> Installing VS Code Extensions..."
    EXTS="ms-python.python ms-python.vscode-pylance ms-python.debugpy charliermarsh.ruff dbaeumer.vscode-eslint rvest.vs-code-prettier-eslint docker.docker ms-azuretools.vscode-docker github.copilot github.copilot-chat eamodio.gitlens github.vscode-pull-request-github ms-vscode-remote.remote-containers bierner.markdown-mermaid naumovs.color-highlight wakatime.vscode-wakatime leonardssh.vscord"

    for ext in $EXTS; do
        echo "   Installing $ext..."
        code --install-extension "$ext" --force || echo "   Failed to install $ext (skipping)"
    done
else
    echo "⚠️  VS Code not found, skipping extensions installation"
fi

# --- 2. MIME TYPE MAPPING ---
echo ">>> Configuring MIME Type Mappings..."
mkdir -p "$HOME/.config"
cat > "$HOME/.config/mimeapps.list" << 'MIMEEOF'
[Default Applications]
text/html=brave-browser.desktop
x-scheme-handler/http=brave-browser.desktop
x-scheme-handler/https=brave-browser.desktop
MIMEEOF

echo "✅ User configurations complete."
EOF

cat "$USER_SCRIPT" | distrobox enter "$BOX_NAME" -- sudo tee /home/$INTERNAL_USER/user-apps.sh > /dev/null
distrobox enter "$BOX_NAME" -- sudo chown $INTERNAL_USER:$INTERNAL_USER /home/$INTERNAL_USER/user-apps.sh
distrobox enter "$BOX_NAME" -- sudo chmod +x /home/$INTERNAL_USER/user-apps.sh
distrobox enter "$BOX_NAME" -- sudo -u "$INTERNAL_USER" /bin/bash /home/$INTERNAL_USER/user-apps.sh

# -----------------------------------------------------------
# CREATE LAUNCHERS
# -----------------------------------------------------------
create_launchers

echo ""
echo "🎉 SUCCESS! Applications installed and configured for '$BOX_NAME'."
echo "💡 Launchers are available in your application menu."

