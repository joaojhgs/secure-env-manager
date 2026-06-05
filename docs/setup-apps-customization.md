# Customizing `setup-apps.sh`

The `setup-apps.sh` script provides a versatile way to install predefined applications or run custom deployment workflows in your isolated environments without needing to directly SSH into the container repeatedly.

## Default Provisioning
By default, running `./setup-apps.sh <env-name>` performs the full standard provisioning of the environment:
1. **Installs core applications:** VS Code, Cursor, Google Chrome, Brave, and Antigravity.
2. **Reconfigures App settings:** Applies Brave & Chrome extensions enforcement via policies, changes MIME type defaults, etc.
3. **Generates Desktop Launchers:** Automatically maps the isolated GUI applications into your host machine using `generate_app_launcher()`.
4. **Installs IDE extensions:** Sets up default tools required for modern software development (Python, Linters, GitHub plugins etc). 

To customize the default provisioning behavior permanently across all your new environments, you can modify the following parts of `setup-apps.sh`:
- **Root Provisioning Block:** Alter the applications listed in the `ROOT_SCRIPT` heredoc block. It covers package manager operations via `apt-get` as `sudo`.
- **User Provisioning Block:** Located at the bottom (`USER_SCRIPT`), use this to set up IDE extensions or configure developer credentials directly on the internal user.
- **`generate_app_launcher()` / `create_launchers()`:** Use this logic block to hardcode more application launchers into your system menu so you can quickly click them on your host.

## Custom Deployments via Options
Instead of the full provisioning, you can bypass the standard sequence and use flags to specifically deploy and map unique tools ad-hoc. 

### Install via `.deb` (`--deb` or `-d`)
Deploy a single `.deb` package localized on your host system to your secure environment:
```bash
./setup-apps.sh <env-name> --deb ~/Downloads/spotify-client.deb
```
*The script copies the `.deb` file inside the container, uses `dpkg -i` to install it, attempts to fix any missing dependencies with `apt-get install -f`, and prompts you to create a desktop launcher mapping the app cleanly to your host UI.*

### Install via Script (`--script` or `-s`)
Execute a custom `.sh` script natively inside the container:
```bash
./setup-apps.sh <env-name> --script ~/dev/team-toolchain-setup.sh
```

### Install via Command (`--cmd` or `-c`)
Inject straightforward bash sequences inside the container context:
```bash
./setup-apps.sh <env-name> --cmd "sudo apt-get update && sudo apt-get install -y neovim htio"
```

### Create New Desktop Launchers (`--launcher-only` or `-l`)
If you've established your own binaries internally via `distrobox enter` and just need standard Host Desktop entries mapping to the X11 configurations in the environment, use:
```bash
./setup-apps.sh <env-name> --launcher-only
```
You will be automatically prompted for:
- **App Name** (e.g., `Slack` or `Spotify`)
- **Launch Command** (e.g., `slack` or `spotify`)
- **Icon ID** (or a system path, defaults to `utilities-terminal`).

## Technical Context: Launching Mechanics
Keep in mind that desktop applications provisioned run fully internally but emit to your screens through `run-as-dev` and interact directly with host socket protocols (like `X11` & `PulseAudio`). If you are creating custom commands manually with `generate_app_launcher()`, verify your X11 ACL permissions, UID mappings, and sound variables are appropriately set on your apps, or they might fail to visualize graphical elements or omit sound.