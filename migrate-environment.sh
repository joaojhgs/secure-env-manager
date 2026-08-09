#!/usr/bin/env bash
set -Eeuo pipefail

# Create a rollback-safe snapshot of a rootless Distrobox and move its active
# Podman storage and isolated developer home to another Linux filesystem.
# The source container and source home are never deleted by this script.

BOX_NAME="${1:-}"
DEST_ROOT="${2:-}"
usage() {
    cat <<'EOF'
Usage: ./migrate-environment.sh <box-name> <destination-root>

Example:
  ./migrate-environment.sh personal /mnt/hdd3/secure-env-manager

The script must be run as the regular user that owns the rootless container.
It will request sudo only to create/chown destination directories. It stops the
container consistently, commits its root filesystem, saves that image, copies
/home/developer with rsync checksums, changes rootless Podman's graphroot, and
loads the snapshot into the new graphroot. It does not delete source data.
EOF
}

if [[ -z "$BOX_NAME" || -z "$DEST_ROOT" ]]; then
    usage >&2
    exit 2
fi
if [[ $EUID -eq 0 ]]; then
    echo "Do not run this script with sudo; run it as the rootless Podman owner." >&2
    exit 2
fi
for command_name in podman rsync sha256sum sudo findmnt; do
    command -v "$command_name" >/dev/null || {
        echo "Missing required command: $command_name" >&2
        exit 1
    }
done
podman container exists "$BOX_NAME" || {
    echo "Rootless Podman container not found: $BOX_NAME" >&2
    exit 1
}

DEST_ROOT="${DEST_ROOT%/}"
ENV_ROOT="$DEST_ROOT/environments/isolated_${BOX_NAME}"
DEST_HOME="$ENV_ROOT/home"
DEST_MASK="$ENV_ROOT/host_mask"
BACKUP_ROOT="$DEST_ROOT/backups/$BOX_NAME"
PODMAN_ROOT="$DEST_ROOT/podman"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
IMAGE="localhost/sem-${BOX_NAME}-migration:$STAMP"
ARCHIVE="$BACKUP_ROOT/${BOX_NAME}-rootfs-${STAMP}.tar"
MANIFEST="$BACKUP_ROOT/${BOX_NAME}-migration-${STAMP}.txt"
SOURCE_HOME="$(podman inspect "$BOX_NAME" --format '{{range .Mounts}}{{if eq .Destination "/home/developer"}}{{.Source}}{{end}}{{end}}')"

if [[ -z "$SOURCE_HOME" || ! -d "$SOURCE_HOME" ]]; then
    echo "Could not resolve the bind-mounted /home/developer source." >&2
    exit 1
fi
DEST_PROBE="$DEST_ROOT"
while [[ ! -e "$DEST_PROBE" && "$DEST_PROBE" != "/" ]]; do
    DEST_PROBE="$(dirname "$DEST_PROBE")"
done
DEST_FSTYPE="$(findmnt -n -o FSTYPE -T "$DEST_PROBE")"
if [[ "$DEST_FSTYPE" != "ext4" ]]; then
    echo "Destination must be on ext4; nearest existing parent resolves to: $(findmnt -n -o FSTYPE,TARGET -T "$DEST_PROBE")" >&2
    exit 1
fi

echo "Source container: $BOX_NAME"
echo "Source developer home: $SOURCE_HOME"
echo "Destination: $DEST_ROOT"
echo "Snapshot image: $IMAGE"
sudo -v
sudo install -d -o "$USER" -g "$USER" "$DEST_ROOT" "$ENV_ROOT" "$BACKUP_ROOT" "$PODMAN_ROOT"
sudo install -d "$DEST_HOME" "$DEST_MASK"

was_running=false
if [[ "$(podman inspect "$BOX_NAME" --format '{{.State.Running}}')" == true ]]; then
    was_running=true
    echo "Stopping $BOX_NAME for a consistent snapshot..."
    distrobox stop "$BOX_NAME" --yes
fi

echo "Committing container root filesystem..."
podman commit "$BOX_NAME" "$IMAGE" >/dev/null
echo "Saving portable root filesystem image..."
podman save --format oci-archive -o "$ARCHIVE" "$IMAGE"
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"

echo "Copying developer home with numeric ownership and filesystem metadata..."
sudo rsync -aHAXS --numeric-ids --delete-delay --info=stats2,progress2 \
    "$SOURCE_HOME/" "$DEST_HOME/"
echo "Verifying developer home content with checksums (this can take time)..."
sudo rsync -aHAXScn --numeric-ids --delete "$SOURCE_HOME/" "$DEST_HOME/" | tee "$BACKUP_ROOT/home-verify-$STAMP.txt"
if [[ -s "$BACKUP_ROOT/home-verify-$STAMP.txt" ]]; then
    echo "Checksum verification reported differences; source data remains untouched." >&2
    exit 1
fi

podman inspect "$BOX_NAME" > "$BACKUP_ROOT/${BOX_NAME}-inspect-${STAMP}.json"
podman exec "$BOX_NAME" true 2>/dev/null || true
{
    echo "box=$BOX_NAME"
    echo "created_utc=$STAMP"
    echo "source_home=$SOURCE_HOME"
    echo "destination_home=$DEST_HOME"
    echo "image=$IMAGE"
    echo "archive=$ARCHIVE"
    echo "archive_sha256=$(cut -d' ' -f1 "$ARCHIVE.sha256")"
    echo "old_graphroot=$(podman info --format '{{.Store.GraphRoot}}')"
    echo "new_graphroot=$PODMAN_ROOT"
    echo "source_preserved=true"
} > "$MANIFEST"

mkdir -p "$HOME/.config/containers"
if [[ -f "$HOME/.config/containers/storage.conf" ]]; then
    cp -a "$HOME/.config/containers/storage.conf" "$BACKUP_ROOT/storage.conf.before-$STAMP"
fi
cat > "$BACKUP_ROOT/storage.conf.new-$STAMP" <<EOF
[storage]
driver = "overlay"
graphroot = "$PODMAN_ROOT"
runroot = "/run/user/$(id -u)/containers"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
install -m 600 "$BACKUP_ROOT/storage.conf.new-$STAMP" "$HOME/.config/containers/storage.conf"

echo "Loading snapshot into the new Podman graphroot..."
podman load -i "$ARCHIVE"
podman image exists "$IMAGE"

echo
echo "Migration snapshot and home copy verified. Source data was not deleted."
echo "New graphroot: $(podman info --format '{{.Store.GraphRoot}}')"
echo "Developer home: $DEST_HOME"
echo "Migration image: $IMAGE"
echo "Manifest: $MANIFEST"
echo
echo "Next, recreate with:"
printf 'SEM_STORAGE_ROOT=%q SEM_IMAGE_ROOT=%q SEM_CONTAINER_IMAGE=%q ./manage-safe-environement.sh create %q\n' \
    "$DEST_ROOT/environments" "$DEST_ROOT/images" "$IMAGE" "$BOX_NAME"
if [[ "$was_running" == true ]]; then
    echo "The old container was running; it remains stopped in the preserved old graphroot."
fi
