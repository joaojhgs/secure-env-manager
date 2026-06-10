#!/bin/bash
set -e

# ==============================================================================
# CONFIGURATION
# ==============================================================================
BOX_NAME=""
INSTALL_DEB=""
INSTALL_SCRIPT=""
INSTALL_CMD=""
LAUNCHER_ONLY="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--deb) INSTALL_DEB="$2"; shift 2 ;;
        -s|--script) INSTALL_SCRIPT="$2"; shift 2 ;;
        -c|--cmd) INSTALL_CMD="$2"; shift 2 ;;
        -l|--launcher-only) LAUNCHER_ONLY="true"; shift 1 ;;
        -h|--help)
            echo "Usage: $0 [env_name] [options]"
            echo "  If no options are provided, runs the standard provisioning (VS Code, Brave, Chrome, etc)."
            echo "Options:"
            echo "  -d, --deb <file>        Install a .deb file into the container and create a shortcut"
            echo "  -s, --script <file>     Run an installation script into the container and create a shortcut"
            echo "  -c, --cmd <command>     Run a specific command interactively inside the container and create a shortcut"
            echo "  -l, --launcher-only     Just create a host shortcut for an already-installed application"
            echo "  -h, --help              Show this help message"
            exit 0
            ;;
        *)
            if [[ -z "$BOX_NAME" ]]; then
                BOX_NAME="$1"
                shift 1
            else
                echo "❌ Unknown argument: $1"
                exit 1
            fi
            ;;
    esac
done

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

function check_container() {


    if ! distrobox list | grep -q "$BOX_NAME"; then
        echo "❌ Error: Container '$BOX_NAME' does not exist."
        echo "   Please create it first using: ./manage-safe-environement.sh create $BOX_NAME"
        exit 1
    fi
}

function generate_app_launcher() {
    local APP_NAME="$1"
    local CMD="$2"
    local ICON="$3"
    local BIN_NAME="${BOX_NAME}-$(echo "$APP_NAME" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')"
    
    cat <<SCRIPT > "/tmp/$BIN_NAME"
#!/bin/bash

# 1. PREPARE X11 KEY
X_FILE="/tmp/.xauth_transfer_\${USER}"
if command -v xauth >/dev/null; then
    xauth nlist \$DISPLAY | sed -e 's/^..../ffff/' > "\$X_FILE"
    chmod 644 "\$X_FILE"
fi

# 2. CALL BRIDGE (pass HOST_UID for audio access)
export HOST_UID=\$(id -u)
CMD_STR="distrobox enter $BOX_NAME -- env HOST_UID=\$HOST_UID XAUTH_SOURCE_FILE=\$X_FILE /usr/local/bin/run-as-dev $CMD \$@"

# Grant Socket Access - SECURITY FIX (CVE-CUSTOM-003)
# Use SI (Server Interpreted) authorization - only authorize current user
if command -v xhost >/dev/null; then
    xhost +SI:localuser:\$(whoami) >/dev/null 2>&1
fi

# Set ACL on X11 socket - SECURITY: DO NOT fall back to world-writable (HSV-002)
if [ -n "\$DISPLAY" ]; then
    SOCKET_NUM=\${DISPLAY#*:} 
    SOCKET_PATH="/tmp/.X11-unix/X\${SOCKET_NUM%.*}"
    if command -v setfacl &> /dev/null && [ -e "\$SOCKET_PATH" ]; then
        # Grand access to the host user (Docker 1:1 mapping cases)
        setfacl -m u:\$(id -u):rw "\$SOCKET_PATH" 2>/dev/null || true
        setfacl -m u:1001:rw "\$SOCKET_PATH" 2>/dev/null || true
        
        # Grant access to the mapped user (Rootless Podman cases)
        SUBUID_START=\$(grep "^\$(whoami):" /etc/subuid 2>/dev/null | cut -d: -f2)
        if [ -n "\$SUBUID_START" ]; then
            REAL_UID=\$((SUBUID_START + 1001 - 1))
            setfacl -m u:\$REAL_UID:rw "\$SOCKET_PATH" 2>/dev/null || echo "Warning: Could not set X11 socket ACL for \$REAL_UID"
        fi
    fi
    # REMOVED: chmod o+w fallback - this is a security risk (HSV-002)
fi

# 3. LAUNCH
# SECURITY: Use secure log location instead of /tmp (MSV-001)
LOG_DIR="\$HOME/.local/log"
mkdir -p "\$LOG_DIR"
chmod 700 "\$LOG_DIR"

if [ -t 0 ]; then
    \$CMD_STR
else
    \$CMD_STR >> "\$LOG_DIR/${BIN_NAME}.log" 2>&1
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

function prompt_and_create_shortcut() {
    echo ""
    echo "🎨 Create a launcher shortcut for your application:"
    read -p "   App Name (e.g., 'Spotify'): " APP_NAME < /dev/tty
    read -p "   Launch Command (e.g., 'spotify'): " APP_CMD < /dev/tty
    read -p "   Icon (e.g. 'utilities-terminal' or file.png. Leave empty to use default): " APP_ICON < /dev/tty
    
    if [ -z "$APP_ICON" ]; then APP_ICON="utilities-terminal"; fi
    if [ -n "$APP_NAME" ] && [ -n "$APP_CMD" ]; then
        generate_app_launcher "$APP_NAME" "$APP_CMD" "$APP_ICON"
        echo "✅ Shortcut created: $APP_NAME - $BOX_NAME"
    else
        echo "⚠️  App Name and Command are required. Skipping shortcut creation."
    fi
}

function configure_openvpn_persistence() {
    # Ensure /run/openvpn is universally recreated via systemd overrides
    # (Distrobox masks systemd-tmpfiles-setup.service on boot, so we inject a pre-start command)
    distrobox enter "$BOX_NAME" -- sudo mkdir -p /etc/systemd/system/openvpn@.service.d
    distrobox enter "$BOX_NAME" -- bash -c 'echo -e "[Service]\nExecStartPre=+/usr/bin/mkdir -p /run/openvpn" | sudo tee /etc/systemd/system/openvpn@.service.d/override.conf >/dev/null'
    distrobox enter "$BOX_NAME" -- sudo systemctl daemon-reload
}

function create_launchers() {
    echo "🚀 Generating launchers..."
    # Using --disable-setuid-sandbox is safe since container doesn't have setuid anyway
    # User-namespace sandbox remains active for protection
    FLAGS="--password-store=basic --disable-setuid-sandbox --disable-dev-shm-usage --ozone-platform=x11 --verbose"
    
    # ELECTRON APP ISOLATION: Use unique user-data-dir per environment
    # This prevents Electron apps (Cursor, VSCode, Chrome) from detecting instances
    # in other containers and redirecting to them (single-instance lock issue)
    ELECTRON_USER_DATA_FLAGS="--user-data-dir=/home/developer/.config/${BOX_NAME}"
    
    # Only create launchers for installed apps
    if distrobox enter "$BOX_NAME" -- command -v code >/dev/null 2>&1; then
        generate_app_launcher "VSCode" "code --wait $FLAGS ${ELECTRON_USER_DATA_FLAGS}-vscode" "com.visualstudio.code"
    fi
    
    if distrobox enter "$BOX_NAME" -- command -v cursor >/dev/null 2>&1; then
        generate_app_launcher "Cursor" "cursor --wait $FLAGS ${ELECTRON_USER_DATA_FLAGS}-cursor" "cursor"
    fi
    
    if distrobox enter "$BOX_NAME" -- command -v brave-browser >/dev/null 2>&1; then
        generate_app_launcher "Brave" "brave-browser $FLAGS ${ELECTRON_USER_DATA_FLAGS}-brave" "brave-browser"
    fi
    
    if distrobox enter "$BOX_NAME" -- command -v google-chrome >/dev/null 2>&1; then
        generate_app_launcher "Chrome" "google-chrome $FLAGS ${ELECTRON_USER_DATA_FLAGS}-chrome" "google-chrome"
    fi
    
    if distrobox enter "$BOX_NAME" -- command -v antigravity >/dev/null 2>&1; then
        # Antigravity is an Electron app, needs same flags as other Electron apps
        generate_app_launcher "Antigravity" "antigravity $FLAGS ${ELECTRON_USER_DATA_FLAGS}-antigravity" "antigravity"
    fi
    
    generate_app_launcher "Terminal" "zsh" "utilities-terminal"
    
    # DRATA LAUNCHER CHECK
    if distrobox enter "$BOX_NAME" -- command -v drata-agent >/dev/null 2>&1; then
         generate_app_launcher "Drata" "drata-agent $FLAGS" "drata-agent"
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



# --- CUSTOM INSTALLATION ROUTING ---
if [ -n "$INSTALL_DEB" ] || [ -n "$INSTALL_SCRIPT" ] || [ -n "$INSTALL_CMD" ] || [ "$LAUNCHER_ONLY" = true ]; then
    echo "⚙️  RUNNING CUSTOM SETTINGS FOR: $BOX_NAME"
    if [ -n "$INSTALL_DEB" ]; then
        echo "📦 Installing DEB package: $INSTALL_DEB"
        if [ ! -f "$INSTALL_DEB" ]; then echo "❌ File not found: $INSTALL_DEB"; exit 1; fi
        ABS_PATH=$(realpath "$INSTALL_DEB")
        BASENAME=$(basename "$ABS_PATH")
        podman cp "$ABS_PATH" "$BOX_NAME:/tmp/$BASENAME"
        distrobox enter "$BOX_NAME" -- sh -c "sudo dpkg -i '/tmp/$BASENAME' || sudo apt-get install -f -y"
        prompt_and_create_shortcut
    elif [ -n "$INSTALL_SCRIPT" ]; then
        echo "📜 Executing script: $INSTALL_SCRIPT"
        if [ ! -f "$INSTALL_SCRIPT" ]; then echo "❌ File not found: $INSTALL_SCRIPT"; exit 1; fi
        ABS_PATH=$(realpath "$INSTALL_SCRIPT")
        BASENAME=$(basename "$ABS_PATH")
        podman cp "$ABS_PATH" "$BOX_NAME:/tmp/$BASENAME"
        distrobox enter "$BOX_NAME" -- bash -c "chmod +x '/tmp/$BASENAME' && '/tmp/$BASENAME'"
        prompt_and_create_shortcut
    elif [ -n "$INSTALL_CMD" ]; then
        echo "⚙️ Running command: $INSTALL_CMD"
        distrobox enter "$BOX_NAME" -- sh -c "$INSTALL_CMD"
        prompt_and_create_shortcut
    elif [ "$LAUNCHER_ONLY" = true ]; then
        prompt_and_create_shortcut
    fi
    echo ""
    echo "🎉 SUCCESS! Custom installation complete for '$BOX_NAME'."
    exit 0
fi

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

# tmux (required by oh-my-claudecode and oh-my-codex team workflows)
if ! command -v tmux &> /dev/null; then
    echo "   Installing tmux..."
    apt-get install -y tmux
fi

# jq (required by RTK wrapper hook for permissionDecision stripping)
if ! command -v jq &> /dev/null; then
    echo "   Installing jq..."
    apt-get install -y jq
fi

# git (required for obsidian-second-brain and other skill clones)
if ! command -v git &> /dev/null; then
    echo "   Installing git..."
    apt-get install -y git
fi

# Antigravity
if ! command -v antigravity &> /dev/null; then
    echo "   Installing Antigravity..."
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://us-central1-apt.pkg.dev/doc/repo-signing-key.gpg | \
        gpg --dearmor --yes -o /etc/apt/keyrings/antigravity-repo-key.gpg
    echo "deb [signed-by=/etc/apt/keyrings/antigravity-repo-key.gpg] https://us-central1-apt.pkg.dev/projects/antigravity-auto-updater-dev/ antigravity-debian main" | \
        tee /etc/apt/sources.list.d/antigravity.list > /dev/null
    apt-get update
    apt-get install -y antigravity
fi

# BRAVE POLICIES & EXTENSIONS
echo ">>> Configuring Brave Policies..."
mkdir -p "/etc/brave/policies/managed" "/etc/opt/chrome/policies/managed"
E_JSON='{ "ExtensionInstallForcelist": [ "oldceeleldhonbafppcapldpdifcinji", "folnjigffmbjmcjgmbbfcpleeddaedal", "cimiefiiaegbelhefglklhhakcgmhkai", "gppongmhjkpfnbhagpmjfkannfbllamg" ] }'
echo "$E_JSON" > "/etc/brave/policies/managed/extensions.json"
echo "$E_JSON" > "/etc/opt/chrome/policies/managed/extensions.json"
chmod -R 755 "/etc/brave" "/etc/opt/chrome"

# Update XDG OPEN WRAPPER to use Brave
# SECURITY: Using --disable-setuid-sandbox instead of --no-sandbox (CVE-CUSTOM-002)
if [ -f "/opt/isolated_wrappers/xdg-open" ]; then
    cat > "/opt/isolated_wrappers/xdg-open" << 'XDGEOF'
#!/bin/bash
echo "[WRAPPER] Opening URL: $1"
if command -v brave-browser >/dev/null 2>&1; then
    exec brave-browser --disable-setuid-sandbox "$1"
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
    read -p "🔹 Do you want to install Drata Agent? (y/N): " INSTALL_DRATA < /dev/tty
    if [[ "$INSTALL_DRATA" =~ ^[Yy]$ ]]; then
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
        echo "⏭️  Skipping Drata Agent installation."
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
application/x-antigravity=antigravity.desktop
MIMEEOF

# --- 3. AI CLIs (Claude Code, Codex, Cursor CLI, oh-my-claude, oh-my-codex, Multica) ---
echo ">>> Installing AI agent CLIs and orchestration tools..."

export ASDF_DIR="$HOME/.asdf"
if [ -f "$HOME/.asdf/asdf.sh" ]; then . "$HOME/.asdf/asdf.sh"; fi

# Ensure user-local bin is on PATH for cursor-agent and multica
mkdir -p "$HOME/.local/bin"
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$HOME/.local/bin"; then
    export PATH="$HOME/.local/bin:$PATH"
fi
for rc in "$HOME/.profile" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && ! grep -qF '$HOME/.local/bin' "$rc"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
    fi
done

if command -v npm >/dev/null 2>&1; then
    echo "   Installing Claude Code and oh-my-claudecode..."
    npm install -g @anthropic-ai/claude-code oh-my-claude-sisyphus@latest || echo "   Failed to install Claude Code tools"

    echo "   Installing OpenAI Codex and oh-my-codex..."
    npm install -g @openai/codex oh-my-codex@latest || echo "   Failed to install OpenAI Codex tools"

    if command -v omc >/dev/null 2>&1; then
        echo "   Running omc setup (oh-my-claudecode skills, agents, hooks)..."
        omc setup --quiet || echo "   omc setup failed (run 'omc setup' manually after provisioning)"
    fi

    if command -v omx >/dev/null 2>&1; then
        echo "   Running omx setup (oh-my-codex skills, prompts, config)..."
        omx setup || echo "   omx setup failed (run 'omx setup' manually after provisioning)"
    fi
else
    echo "⚠️ npm is not available. Skipping npm-based AI CLI installations."
fi

# Cursor CLI (cursor-agent) — separate from the Cursor IDE .deb
if ! command -v cursor-agent >/dev/null 2>&1; then
    echo "   Installing Cursor CLI (cursor-agent)..."
    curl -fsSL https://cursor.com/install | bash || echo "   Failed to install Cursor CLI"
else
    echo "   Cursor CLI already installed."
fi

# Multica CLI only (no self-hosted server)
if ! command -v multica >/dev/null 2>&1; then
    echo "   Installing Multica CLI..."
    MULTICA_BIN_DIR="$HOME/.local/bin" \
        curl -fsSL https://raw.githubusercontent.com/multica-ai/multica/main/scripts/install.sh | bash \
        || echo "   Failed to install Multica CLI"
else
    echo "   Multica CLI already installed."
fi

# Copy a skill folder into every agent's global skills directory
install_skill_to_all_agents() {
    local skill_name="$1"
    local skill_src="$2"
    local agent_skill_dirs=(
        "$HOME/.claude/skills"
        "$HOME/.codex/skills"
        "$HOME/.cursor/skills"
        "$HOME/.agents/skills"
    )
    if [ ! -f "$skill_src/SKILL.md" ]; then
        echo "   $skill_name: no SKILL.md at $skill_src (skipped)."
        return 1
    fi
    for dest_root in "${agent_skill_dirs[@]}"; do
        mkdir -p "$dest_root"
        rm -rf "$dest_root/$skill_name"
        cp -r "$skill_src" "$dest_root/$skill_name"
    done
    echo "   Installed skill: $skill_name (claude, codex, cursor, .agents)"
}

# token-savings skill — fetched from upstream repo at provisioning time
install_token_savings_skill() {
    local cache="$HOME/.cache/token-savings"
    local base="https://raw.githubusercontent.com/andrew-tenkara/CLAUDE-MD/main/skills/token-savings"
    rm -rf "$cache"
    mkdir -p "$cache/scripts"
    curl -fsSL "$base/SKILL.md" -o "$cache/SKILL.md" \
        && curl -fsSL "$base/scripts/preflight.sh" -o "$cache/scripts/preflight.sh" \
        && curl -fsSL "$base/scripts/dashboard.sh" -o "$cache/scripts/dashboard.sh" \
        && curl -fsSL "$base/scripts/tui.py" -o "$cache/scripts/tui.py" \
        && chmod +x "$cache/scripts/"*.sh \
        && install_skill_to_all_agents "token-savings" "$cache" \
        && echo "   Installed skill: token-savings (from andrew-tenkara/CLAUDE-MD)" \
        || echo "   Failed to install token-savings skill from $base"
}

echo "   Installing token-savings skill from GitHub..."
install_token_savings_skill || echo "   Failed to install token-savings skill"

# Agentmemory, CodeGraph, taste-skill, obsidian-second-brain
install_agent_plugins() {
    export CI=1

    # --- agentmemory: persistent memory + MCP ---
    if command -v npm >/dev/null 2>&1; then
        echo "   Installing agentmemory..."
        npm install -g @agentmemory/agentmemory || echo "   Failed to install agentmemory npm package"

        if command -v agentmemory >/dev/null 2>&1; then
            if ! curl -fsS http://localhost:3111/agentmemory/livez >/dev/null 2>&1; then
                echo "   Starting agentmemory server..."
                nohup agentmemory >/tmp/agentmemory.log 2>&1 &
                for _ in $(seq 1 15); do
                    curl -fsS http://localhost:3111/agentmemory/livez >/dev/null 2>&1 && break
                    sleep 1
                done
            fi

            if command -v claude >/dev/null 2>&1; then
                agentmemory connect claude-code || echo "   agentmemory connect claude-code failed"
            fi
            if command -v codex >/dev/null 2>&1; then
                agentmemory connect codex --with-hooks 2>/dev/null || agentmemory connect codex || echo "   agentmemory connect codex failed"
                codex plugin marketplace add rohitg00/agentmemory 2>/dev/null || true
                codex plugin add agentmemory@agentmemory 2>/dev/null || true
            fi
            if command -v cursor-agent >/dev/null 2>&1 || command -v cursor >/dev/null 2>&1; then
                agentmemory connect cursor || echo "   agentmemory connect cursor failed"
            fi

            npx skills add rohitg00/agentmemory -y -a '*' 2>/dev/null \
                || npx skills add rohitg00/agentmemory -y 2>/dev/null \
                || echo "   Failed to install agentmemory skills"
        fi
    fi

    # --- codegraph: semantic code intelligence MCP ---
    if ! command -v codegraph >/dev/null 2>&1; then
        echo "   Installing CodeGraph CLI..."
        curl -fsSL https://raw.githubusercontent.com/colbymchenry/codegraph/main/install.sh | sh \
            || echo "   Failed to install CodeGraph"
    fi
    export PATH="$HOME/.local/bin:$PATH"
    if command -v codegraph >/dev/null 2>&1; then
        echo "   Configuring CodeGraph for claude, codex, cursor..."
        codegraph install --target=claude,cursor,codex --yes 2>/dev/null \
            || codegraph install --target=auto --yes 2>/dev/null \
            || codegraph install --yes 2>/dev/null \
            || echo "   codegraph install failed"
    fi

    # --- taste-skill: anti-slop frontend design skills ---
    if command -v npx >/dev/null 2>&1; then
        echo "   Installing taste-skill for all agents..."
        npx skills add https://github.com/Leonxlnx/taste-skill -y -a '*' 2>/dev/null \
            || npx skills add https://github.com/Leonxlnx/taste-skill -y 2>/dev/null \
            || echo "   Failed to install taste-skill"
    fi

    # --- obsidian-second-brain: cross-CLI Obsidian vault skill ---
    local obsidian_skill="$HOME/.claude/skills/obsidian-second-brain"
    echo "   Installing obsidian-second-brain..."
    if [ -d "$obsidian_skill/.git" ]; then
        git -C "$obsidian_skill" pull --ff-only 2>/dev/null || true
    else
        rm -rf "$obsidian_skill"
        git clone https://github.com/eugeniughelbur/obsidian-second-brain "$obsidian_skill" \
            || echo "   Failed to clone obsidian-second-brain"
    fi
    if [ -d "$obsidian_skill" ]; then
        install_skill_to_all_agents "obsidian-second-brain" "$obsidian_skill" || true
        chmod +x "$obsidian_skill"/hooks/*.sh 2>/dev/null || true
        chmod +x "$obsidian_skill"/hooks/*.py 2>/dev/null || true
        bash "$obsidian_skill/scripts/install-codex-wrappers.sh" 2>/dev/null || true
        if [ -n "${OBSIDIAN_VAULT_PATH:-}" ] && [ -d "${OBSIDIAN_VAULT_PATH/#\~/$HOME}" ]; then
            bash "$obsidian_skill/scripts/setup.sh" "${OBSIDIAN_VAULT_PATH/#\~/$HOME}" \
                || echo "   obsidian-second-brain setup.sh failed"
        else
            echo "   obsidian-second-brain: set OBSIDIAN_VAULT_PATH and run scripts/setup.sh to wire your vault"
        fi
    fi
}

echo "   Installing agentmemory, CodeGraph, taste-skill, obsidian-second-brain..."
install_agent_plugins || echo "   Failed to configure some agent plugins"

# RTK + Headroom token savings stack (Claude Code hooks)
# See: https://andrewpatterson.dev/posts/token-savings-rtk-headroom/
install_token_savings_stack() {
    local hooks_dir="$HOME/.claude/hooks"
    local settings="$HOME/.claude/settings.json"
    mkdir -p "$hooks_dir"

    # RTK — filters Bash command output before it enters context (PreToolUse)
    if ! command -v rtk >/dev/null 2>&1; then
        echo "   Installing RTK (Rust Token Killer)..."
        curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/refs/heads/master/install.sh | sh \
            || echo "   Failed to install RTK"
    fi

    if command -v rtk >/dev/null 2>&1; then
        echo "   Wiring RTK Claude Code hook..."
        rtk init -g --auto-patch 2>/dev/null || rtk init -g --hook-only 2>/dev/null || true

        # Wrapper survives rtk init -g regenerations and strips permissionDecision (silent savings killer)
        cat > "$hooks_dir/rtk-wrapper.sh" << 'RTKWRAPPER'
#!/usr/bin/env bash
export PATH="$HOME/.local/bin:/usr/local/bin:$HOME/.cargo/bin:$PATH"

OUTPUT=$(bash "$(dirname "$0")/rtk-rewrite.sh" "$@")
EXIT_CODE=$?

if [ -z "$OUTPUT" ] || [ $EXIT_CODE -ne 0 ]; then
    exit $EXIT_CODE
fi

echo "$OUTPUT" | jq '
  if .hookSpecificOutput then
    .hookSpecificOutput |= del(.permissionDecision, .permissionDecisionReason)
  else
    .
  end
' 2>/dev/null || echo "$OUTPUT"

exit $EXIT_CODE
RTKWRAPPER
        chmod +x "$hooks_dir/rtk-wrapper.sh"
    fi

    # Headroom — compresses API context via local proxy (SessionStart)
    if command -v python3 >/dev/null 2>&1; then
        echo "   Installing Headroom proxy..."
        python3 -m pip install --user "headroom-ai[proxy]" rich 2>/dev/null \
            || pip install --user "headroom-ai[proxy]" rich 2>/dev/null \
            || echo "   Failed to install Headroom"
    fi

    cat > "$hooks_dir/headroom-autostart.sh" << 'HEADROOMHOOK'
#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

PORT=8787
HEALTH_URL="http://localhost:${PORT}/health"

if ! curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    headroom proxy --port "$PORT" >/dev/null 2>&1 &
    for _ in $(seq 1 15); do
        curl -sf "$HEALTH_URL" >/dev/null 2>&1 && break
        sleep 1
    done
fi

if [[ -n "${CLAUDE_ENV_FILE:-}" ]]; then
    echo "export ANTHROPIC_BASE_URL=http://localhost:${PORT}" >> "$CLAUDE_ENV_FILE"
    echo "export NO_PROXY=localhost,127.0.0.1" >> "$CLAUDE_ENV_FILE"
fi

exit 0
HEADROOMHOOK
    chmod +x "$hooks_dir/headroom-autostart.sh"

    # Merge hooks into settings.json — RTK PreToolUse must be LAST among Bash matchers
    if command -v jq >/dev/null 2>&1; then
        if [ ! -f "$settings" ]; then
            echo '{}' > "$settings"
        fi
        tmp_settings="$(mktemp)"
        jq --arg rtk "bash $hooks_dir/rtk-wrapper.sh" \
           --arg headroom "bash $hooks_dir/headroom-autostart.sh" '
          .hooks //= {} |
          .hooks.SessionStart //= [] |
          if ([.hooks.SessionStart[]? | select(.hooks[]?.command? | test("headroom"))] | length) == 0 then
            .hooks.SessionStart += [{"hooks": [{"type": "command", "command": $headroom}]}]
          else . end |
          .hooks.PreToolUse //= [] |
          .hooks.PreToolUse |= map(
            if .matcher == "Bash" then
              .hooks |= map(select(.command | test("rtk-wrapper") | not))
            else . end
          ) |
          .hooks.PreToolUse += [{"matcher": "Bash", "hooks": [{"type": "command", "command": $rtk}]}]
        ' "$settings" > "$tmp_settings" && mv "$tmp_settings" "$settings"
        echo "   RTK + Headroom hooks registered in ~/.claude/settings.json"
    else
        echo "   jq not available — wire RTK/Headroom hooks manually or run /token-savings in Claude Code"
    fi
}

echo "   Setting up RTK + Headroom token savings..."
install_token_savings_stack || echo "   Failed to configure token savings stack"

if command -v multica >/dev/null 2>&1; then
    echo "   Multica CLI installed. Run 'multica setup' after provisioning to log in and start the daemon."
fi

echo "✅ AI agent CLIs and skills configured."

echo "✅ User configurations complete."
EOF

cat "$USER_SCRIPT" | distrobox enter "$BOX_NAME" -- sudo tee /home/$INTERNAL_USER/user-apps.sh > /dev/null
distrobox enter "$BOX_NAME" -- sudo chown $INTERNAL_USER:$INTERNAL_USER /home/$INTERNAL_USER/user-apps.sh
distrobox enter "$BOX_NAME" -- sudo chmod +x /home/$INTERNAL_USER/user-apps.sh
distrobox enter "$BOX_NAME" -- sudo -u "$INTERNAL_USER" /bin/bash /home/$INTERNAL_USER/user-apps.sh

# -----------------------------------------------------------
# RECONFIGURE SYSTEMD-TMPFILES (OpenVPN Auto-Connection)
# -----------------------------------------------------------
configure_openvpn_persistence

# -----------------------------------------------------------
# CREATE LAUNCHERS
# -----------------------------------------------------------
create_launchers

echo ""
echo "🎉 SUCCESS! Applications installed and configured for '$BOX_NAME'."
echo "💡 Launchers are available in your application menu."