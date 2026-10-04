#!/bin/bash
set -e


# ==============================================================================
# PORTABLE MIGRATION / TRANSFER COMMANDS
# ==============================================================================
SUPPORTED_BUNDLE_VERSION=3
SEM_CLEANUP_STAGING=""
SEM_CLEANUP_OUTPUT_TMP=""
SEM_CLEANUP_IMAGE=""
SEM_CLEANUP_BOX=""
SEM_CLEANUP_RESTART=false

cleanup_export() {
    if [[ "$SEM_CLEANUP_RESTART" == true && -n "$SEM_CLEANUP_BOX" ]]; then
        # A cancelled podman commit/save can leave the overlay mount attached.
        podman unmount "$SEM_CLEANUP_BOX" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SEM_CLEANUP_IMAGE" ]]; then
        podman image rm "$SEM_CLEANUP_IMAGE" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SEM_CLEANUP_STAGING" ]]; then
        rm -rf -- "$SEM_CLEANUP_STAGING"
    fi
    if [[ -n "$SEM_CLEANUP_OUTPUT_TMP" ]]; then
        rm -f -- "$SEM_CLEANUP_OUTPUT_TMP"
    fi
    # Free failed staging/output before restarting: ENOSPC must not leave the
    # original unable to create its runtime/journal files during recovery.
    if [[ "$SEM_CLEANUP_RESTART" == true && -n "$SEM_CLEANUP_BOX" ]]; then
        podman start "$SEM_CLEANUP_BOX" >/dev/null 2>&1 || true
    fi
}

cleanup_import() {
    if [[ -n "$SEM_CLEANUP_STAGING" ]]; then
        rm -rf -- "$SEM_CLEANUP_STAGING"
    fi
}

usage() {
    cat <<'EOF'
Portable, encrypted Distrobox transfer bundles.

Usage:
  ./manage-safe-environement.sh export <box> <bundle.gpg> [export-options]
  ./manage-safe-environement.sh import <bundle.gpg> <storage-root> [new-box-name]
  ./manage-safe-environement.sh send <bundle.gpg> <ssh-destination>

Examples:
  # Password-encrypted bundle (GPG prompts for the password)
  ./manage-safe-environement.sh export personal /mnt/backup/personal.sem.tar.gpg

  # Encrypt to a GPG public key instead
  ./manage-safe-environement.sh export personal personal.sem.tar.gpg \
      --recipient user@example.com

  # Copy the encrypted bundle and checksum over SSH
  ./manage-safe-environement.sh send personal.sem.tar.gpg user@new-pc:/srv/transfers/

  # On the destination computer
  ./manage-safe-environement.sh import personal.sem.tar.gpg \
      /mnt/hdd2/secure-env-manager personal

The bundle contains a portable OCI image, the isolated developer home with
container-relative ownership/ACLs/xattrs, the source container definition, a
manifest, and checksums. Import never deletes an existing container or home.

Export options:
  --recipient <gpg-id>        Encrypt to a public key instead of a password.
  --passphrase-file <file>    Noninteractive encryption; owned regular mode 0600.
  --exclude-file <file>       Exact regenerable paths relative to developer home.
  --stream-home              Avoid staging a second full home archive (v3).
  --keep-snapshot            Retain the OCI image and write a .snapshot sidecar.
  --leave-stopped            Leave the box stopped ONLY after successful export.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

require_commands() {
    local command_name
    for command_name in "$@"; do
        command -v "$command_name" >/dev/null || die "missing command: $command_name"
    done
}

nearest_existing_path() {
    local probe="$1"
    while [[ ! -e "$probe" && "$probe" != "/" ]]; do
        probe="$(dirname "$probe")"
    done
    printf '%s\n' "$probe"
}

verify_linux_destination() {
    local destination="$1" probe fstype
    probe="$(nearest_existing_path "$destination")"
    fstype="$(findmnt -n -o FSTYPE -T "$probe")"
    case "$fstype" in
        ext2|ext3|ext4|xfs|btrfs) ;;
        *) die "destination must be on a native Linux filesystem; found '$fstype' at '$probe'" ;;
    esac
}

export_bundle() {
    [[ $# -ge 2 ]] || { usage >&2; exit 2; }
    local box="$1" output="$2" recipient="" passphrase_file="" exclude_file="" keep_snapshot=false leave_stopped=false stream_home=false bundle_version=2
    shift 2
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --recipient)
                [[ $# -ge 2 ]] || die "--recipient requires a GPG identity"
                recipient="$2"
                shift 2
                ;;
            --passphrase-file)
                [[ $# -ge 2 ]] || die "--passphrase-file requires a protected file"
                passphrase_file="$2"
                [[ -f "$passphrase_file" && ! -L "$passphrase_file" && $(stat -c %u "$passphrase_file") == "$(id -u)" && $(stat -c %a "$passphrase_file") == 600 ]] || die 'Passphrase file must be owned by you, regular, and mode 0600.'
                shift 2
                ;;
            --exclude-file)
                [[ $# -ge 2 && -f "$2" ]] || die '--exclude-file requires an explicit list of regenerable paths relative to the developer home.'
                exclude_file="$(realpath "$2")"
                shift 2
                ;;
            --keep-snapshot) keep_snapshot=true; shift ;;
            --leave-stopped) leave_stopped=true; shift ;;
            --stream-home) stream_home=true; bundle_version=3; shift ;;
            *) die "unknown export option: $1" ;;
        esac
    done
    [[ -z "$recipient" || -z "$passphrase_file" ]] || die 'Choose recipient or passphrase file, not both.'

    require_commands podman distrobox gpg tar zstd sha256sum mktemp python3
    [[ $EUID -ne 0 ]] || die "run as the regular rootless Podman user, not root"
    podman container exists "$box" || die "container not found: $box"
    [[ ! -e "$output" ]] || die "output already exists: $output"
    mkdir -p "$(dirname "$output")"

    local staging stamp image source_home source_mask was_running=false developer_uid developer_gid owner_pair
    staging="$(mktemp -d "$(dirname "$output")/.sem-export.XXXXXX")"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    image="localhost/sem-${box}-transfer:${stamp}"
    SEM_CLEANUP_STAGING="$staging"
    SEM_CLEANUP_OUTPUT_TMP="$output.tmp"
    SEM_CLEANUP_IMAGE="$image"
    SEM_CLEANUP_BOX="$box"
    trap cleanup_export EXIT
    trap 'exit 130' INT TERM HUP
    source_home="$(podman inspect "$box" --format '{{range .Mounts}}{{if eq .Destination "/home/developer"}}{{.Source}}{{end}}{{end}}')"
    [[ -n "$source_home" && -d "$source_home" ]] || die "could not resolve /home/developer bind mount"
    # The administrative compatibility home is a second persistent bind, NOT
    # part of the OCI root filesystem. Preserve it in the recovery package too.
    source_mask="$(podman inspect "$box" | python3 -c 'import json,sys; d=json.load(sys.stdin)[0]; print(next((m["Source"] for m in d["Mounts"] if m["Type"] == "bind" and m["Destination"].endswith("/host_mask")), ""))')"
    [[ -z "$source_mask" || ( -d "$source_mask" && ! -L "$source_mask" ) ]] || die 'Invalid administrative home mount'
    owner_pair="$(podman unshare stat -c '%u:%g' "$source_home")"
    developer_uid="${owner_pair%%:*}"
    developer_gid="${owner_pair##*:}"

    # Validate persistent storage in the rootless user namespace BEFORE downtime.
    # Guest-root volumes can have a mapped UID and a 0700 parent; the ordinary
    # host user cannot stat those even though Podman can safely archive them.
    podman inspect "$box" | python3 -c 'import json,sys; d=json.load(sys.stdin)[0]; json.dump([m for m in d["Mounts"] if m["Type"] == "volume" and m["Destination"] != "/dev/pts"], sys.stdout)' > "$staging/persistent-volumes.json"
    local volume_source
    while IFS= read -r volume_source; do
        podman unshare bash -c '[[ -d "$1" && ! -L "$1" ]]' _ "$volume_source" || die 'Invalid persistent volume source'
    done < <(python3 -c 'import json,sys; [print(m["Source"]) for m in json.load(open(sys.argv[1]))]' "$staging/persistent-volumes.json")

    if [[ "$(podman inspect "$box" --format '{{.State.Running}}')" == true ]]; then
        was_running=true
        SEM_CLEANUP_RESTART=true
        echo "Stopping $box for a consistent export..."
        distrobox stop "$box" --yes
    fi
    echo "Creating OCI image snapshot..."
    TMPDIR="$staging" podman commit "$box" "$image" >/dev/null
    # Compress the OCI archive too: staging an uncompressed installed system can
    # exhaust the very filesystem this backup is meant to protect.
    set -o pipefail
    TMPDIR="$staging" podman save --format oci-archive "$image" | zstd -T2 -3 -o "$staging/rootfs.oci.tar.zst"

    if [[ -n "$source_mask" ]]; then
        echo "Archiving persistent administrative compatibility home..."
        podman unshare tar --acls --xattrs --numeric-owner --sparse -cpf - -C "$source_mask" . |
            zstd -T2 -3 -o "$staging/administrative-home.tar.zst"
    fi

    # Preserve persistent named-volume contents as well as their definitions.
    # /dev/pts is a live kernel terminal filesystem, not persistent user data.
    local volume_index=0
    while IFS= read -r volume_source; do
        podman unshare bash -c '[[ -d "$1" && ! -L "$1" ]]' _ "$volume_source" || die 'Invalid persistent volume source'
        echo "Archiving persistent volume $volume_index..."
        podman unshare tar --acls --xattrs --numeric-owner --sparse -cpf - -C "$volume_source" . |
            zstd -T2 -3 -o "$staging/persistent-volume-$volume_index.tar.zst"
        volume_index=$((volume_index + 1))
    done < <(python3 -c 'import json,sys; [print(m["Source"]) for m in json.load(open(sys.argv[1]))]' "$staging/persistent-volumes.json")

    echo "Archiving developer home with container-relative ownership..."
    local -a tar_excludes=()
    if [[ -n "$exclude_file" ]]; then
        cp -- "$exclude_file" "$staging/home-exclusions.txt"
        tar_excludes=(--no-wildcards --exclude-from="$staging/home-exclusions.txt")
    else
        touch "$staging/home-exclusions.txt"
    fi
    if [[ "$stream_home" == false ]]; then
        podman unshare tar --acls --xattrs --numeric-owner --sparse "${tar_excludes[@]}" -cpf - \
            -C "$source_home" . | zstd -T2 -3 -o "$staging/developer-home.tar.zst"
    fi

    podman inspect "$box" > "$staging/container-inspect.json"
    cat > "$staging/manifest.env" <<EOF
BUNDLE_VERSION=$bundle_version
BOX_NAME=$box
CREATED_UTC=$stamp
IMAGE_REF=$image
HOME_DESTINATION=/home/developer
DEVELOPER_UID=$developer_uid
DEVELOPER_GID=$developer_gid
SOURCE_HOME=$source_home
SOURCE_ADMINISTRATIVE_HOME=$source_mask
EOF
    local -a bundle_members=(manifest.env SHA256SUMS rootfs.oci.tar.zst container-inspect.json home-exclusions.txt persistent-volumes.json)
    [[ -z "$source_mask" ]] || bundle_members+=(administrative-home.tar.zst)
    local volume_count=$volume_index
    for ((volume_index=0; volume_index<volume_count; volume_index++)); do
        bundle_members+=("persistent-volume-$volume_index.tar.zst")
    done
    local -a checked_members=()
    local member
    for member in "${bundle_members[@]}"; do
        [[ "$member" == SHA256SUMS ]] || checked_members+=("$member")
    done
    if [[ "$stream_home" == true ]]; then
        (cd "$staging" && sha256sum "${checked_members[@]}" > SHA256SUMS)
    else
        bundle_members+=(developer-home.tar.zst)
        checked_members+=(developer-home.tar.zst)
        (cd "$staging" && sha256sum "${checked_members[@]}" > SHA256SUMS)
    fi
    emit_bundle() {
        if [[ "$stream_home" == true ]]; then
            # Version 3 avoids keeping a second full home archive. GPG integrity,
            # zstd's checksum and the final encrypted-file SHA cover every home
            # byte; SHA256SUMS additionally verifies staged metadata/image files.
            podman unshare tar --acls --xattrs --numeric-owner --sparse "${tar_excludes[@]}" \
                --transform='flags=rh;s,^\.$,home,;s,^\./,home/,' -cpf - -C "$staging" "${bundle_members[@]}" \
                -C "$source_home" . | zstd -T2 -3
        else
            tar -C "$staging" -cpf - "${bundle_members[@]}"
        fi
    }

    echo "Encrypting transfer bundle..."
    if [[ -n "$recipient" ]]; then
        emit_bundle |
            gpg --batch --yes --encrypt --recipient "$recipient" --output "$output.tmp"
    else
        local -a gpg_passphrase_options=()
        [[ -z "$passphrase_file" ]] || gpg_passphrase_options=(--batch --pinentry-mode loopback --passphrase-file "$passphrase_file")
        emit_bundle |
            gpg "${gpg_passphrase_options[@]}" \
                --symmetric --cipher-algo AES256 --compress-algo none --output "$output.tmp"
    fi
    mv "$output.tmp" "$output"
    (cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
    chmod 600 "$output" "$output.sha256"
    if [[ "$keep_snapshot" == true ]]; then
        printf '%s\n' "$image" > "$output.snapshot"
        chmod 600 "$output.snapshot"
        SEM_CLEANUP_IMAGE=""
    fi
    # Failures still restart the original. Only a successfully encrypted backup
    # may hand an already-stopped container to a deliberate cutover transaction.
    [[ "$leave_stopped" != true ]] || SEM_CLEANUP_RESTART=false
    echo "Bundle: $output"
    echo "Checksum: $output.sha256"
}

import_bundle() {
    [[ $# -ge 2 && $# -le 3 ]] || { usage >&2; exit 2; }
    local bundle="$1" storage_root="${2%/}" requested_name="${3:-}"
    require_commands podman gpg tar zstd sha256sum mktemp findmnt sudo python3
    [[ $EUID -ne 0 ]] || die "run as the regular rootless Podman user, not root"
    [[ -f "$bundle" ]] || die "bundle not found: $bundle"
    if [[ -f "$bundle.sha256" ]]; then
        (cd "$(dirname "$bundle")" && sha256sum -c "$(basename "$bundle").sha256")
    fi
    verify_linux_destination "$storage_root"

    local staging box image developer_uid developer_gid env_root dest_home dest_mask
    # A streamed home must restore on disk, not accidentally fill host tmpfs.
    sudo -v
    sudo install -d -o "$USER" -g "$USER" "$storage_root"
    staging="$(mktemp -d "$storage_root/.sem-import.XXXXXX")"
    SEM_CLEANUP_STAGING="$staging"
    trap cleanup_import EXIT
    trap 'exit 130' INT TERM HUP
    echo "Decrypting bundle..."
    set -o pipefail
    # -dfc passes old uncompressed outer tar through unchanged; v3 is zstd.
    gpg --decrypt "$bundle" | zstd -dfc | podman unshare tar --acls --xattrs --same-owner -xpf - -C "$staging"
    # Old outer archives used the source host UID for these metadata files. Do
    # not confuse that with container-relative home ownership; normalize ONLY
    # known staging metadata so the destination Podman owner can read it.
    local metadata
    for metadata in manifest.env SHA256SUMS container-inspect.json home-exclusions.txt rootfs.oci.tar rootfs.oci.tar.zst developer-home.tar.zst administrative-home.tar.zst persistent-volumes.json; do
        [[ ! -f "$staging/$metadata" || -L "$staging/$metadata" ]] || podman unshare chown 0:0 "$staging/$metadata"
    done
    for metadata in "$staging"/persistent-volume-[0-9]*.tar.zst; do
        [[ ! -f "$metadata" || -L "$metadata" ]] || podman unshare chown 0:0 "$metadata"
    done
    [[ -f "$staging/manifest.env" && -f "$staging/SHA256SUMS" ]] || die "invalid transfer bundle"
    (cd "$staging" && sha256sum -c SHA256SUMS)

    local bundle_version source_box
    bundle_version="$(sed -n 's/^BUNDLE_VERSION=//p' "$staging/manifest.env")"
    source_box="$(sed -n 's/^BOX_NAME=//p' "$staging/manifest.env")"
    image="$(sed -n 's/^IMAGE_REF=//p' "$staging/manifest.env")"
    developer_uid="$(sed -n 's/^DEVELOPER_UID=//p' "$staging/manifest.env")"
    developer_gid="$(sed -n 's/^DEVELOPER_GID=//p' "$staging/manifest.env")"
    [[ "$bundle_version" == 1 || "$bundle_version" == 2 || "$bundle_version" == "$SUPPORTED_BUNDLE_VERSION" ]] || die "unsupported bundle version: ${bundle_version:-missing}"
    [[ "$source_box" =~ ^[a-zA-Z0-9_.-]+$ ]] || die "invalid box name in manifest"
    [[ "$image" =~ ^[a-zA-Z0-9_./:-]+$ ]] || die "invalid image reference in manifest"
    [[ "$developer_uid" =~ ^[0-9]+$ && "$developer_gid" =~ ^[0-9]+$ ]] || die "invalid developer ownership in manifest"
    box="${requested_name:-$source_box}"
    [[ "$box" =~ ^[a-zA-Z0-9_.-]+$ ]] || die "invalid destination box name"
    env_root="$storage_root/environments/isolated_${box}"
    dest_home="$env_root/home"
    dest_mask="$env_root/host_mask"

    podman container exists "$box" && die "destination container already exists: $box"
    [[ ! -e "$dest_home" ]] || die "destination home already exists: $dest_home"
    sudo -v
    sudo install -d -o "$USER" -g "$USER" "$storage_root" "$storage_root/environments" "$env_root" "$dest_home" "$dest_mask"
    sudo chown "$USER:$USER" "$env_root" "$dest_home" "$dest_mask"

    echo "Restoring developer home through the destination Podman user namespace..."
    if [[ "$bundle_version" == 3 ]]; then
        [[ -d "$staging/home" && ! -L "$staging/home" ]] || die 'Streamed developer home is missing.'
        rmdir -- "$dest_home"
        podman unshare mv -- "$staging/home" "$dest_home"
    else
        zstd -dc "$staging/developer-home.tar.zst" |
            podman unshare tar --acls --xattrs --same-owner --sparse -xpf - -C "$dest_home"
    fi
    podman unshare chown "$developer_uid:$developer_gid" "$dest_home"
    if [[ -f "$staging/administrative-home.tar.zst" ]]; then
        echo "Restoring administrative compatibility home..."
        zstd -dc "$staging/administrative-home.tar.zst" |
            podman unshare tar --acls --xattrs --same-owner --sparse -xpf - -C "$dest_mask"
    fi
    if [[ -f "$staging/persistent-volumes.json" ]]; then
        echo "Restoring persistent volume data (not automatically attached)..."
        local volume_destination volume_index=0
        mkdir -m 0700 "$env_root/imported-volumes"
        while IFS= read -r volume_destination; do
            local volume_archive="$staging/persistent-volume-$volume_index.tar.zst"
            [[ -f "$volume_archive" ]] || die 'Missing persistent volume archive'
            podman unshare chown 0:0 "$volume_archive"
            mkdir -m 0700 "$env_root/imported-volumes/$volume_index"
            zstd -dc "$volume_archive" |
                podman unshare tar --acls --xattrs --same-owner --sparse -xpf - -C "$env_root/imported-volumes/$volume_index"
            volume_index=$((volume_index + 1))
        done < <(python3 -c 'import json,sys; [print(m["Destination"]) for m in json.load(open(sys.argv[1]))]' "$staging/persistent-volumes.json")
        install -m 0600 "$staging/persistent-volumes.json" "$env_root/imported-volumes/mount-definitions.json"
    fi

    echo "Loading OCI image..."
    if [[ "$bundle_version" == 1 ]]; then
        podman load -i "$staging/rootfs.oci.tar"
    else
        set -o pipefail
        zstd -dc "$staging/rootfs.oci.tar.zst" | podman load
    fi
    podman image exists "$image" || die "loaded image was not found: $image"

    install -m 600 "$staging/manifest.env" "$env_root/import-manifest.env"
    echo "Import complete; no container was created automatically."
    echo "Image: $image"
    echo "Developer home: $dest_home"
    echo "Create the environment with:"
    printf 'SEM_STORAGE_ROOT=%q SEM_IMAGE_ROOT=%q SEM_CONTAINER_IMAGE=%q ./manage-safe-environement.sh create %q\n' \
        "$storage_root/environments" "$storage_root/images" "$image" "$box"
}

send_bundle() {
    [[ $# -eq 2 ]] || { usage >&2; exit 2; }
    local bundle="$1" destination="$2"
    require_commands scp
    [[ -f "$bundle" ]] || die "bundle not found: $bundle"
    [[ -f "$bundle.sha256" ]] || die "checksum not found: $bundle.sha256"
    scp -- "$bundle" "$bundle.sha256" "$destination"
}

transfer_environment_main() {
    case "${1:-}" in
        export) shift; export_bundle "$@" ;;
        import) shift; import_bundle "$@" ;;
        send) shift; send_bundle "$@" ;;
        help|-h|--help|"") usage ;;
        *) usage >&2; die "unknown transfer command: $1" ;;
    esac
}

migrate_environment_main() {
# Create a rollback-safe snapshot of a rootless Distrobox and move its active
# Podman storage and isolated developer home to another Linux filesystem.
# The source container and source home are never deleted by this script.

BOX_NAME="${1:-}"
DEST_ROOT="${2:-}"
usage() {
    cat <<'EOF'
Usage: ./manage-safe-environement.sh migrate <box-name> <destination-root>

Example:
  ./manage-safe-environement.sh migrate personal /mnt/hdd2/secure-env-manager

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
}

case "${1:-}" in
    export|import|send)
        transfer_environment_main "$@"
        exit $?
        ;;
    migrate)
        shift
        migrate_environment_main "$@"
        exit $?
        ;;
esac

# ==============================================================================
# CONFIGURATION
# ==============================================================================
ACTION="${1:-help}"
BOX_NAME="${2:-}"

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
[[ "$BOX_NAME" =~ ^[a-z][a-z0-9_-]{0,21}$ ]] || die 'Environment name must start with a lowercase letter and contain at most 22 lowercase letters, digits, underscores or hyphens.'
SEM_ALLOW_SHARED_DEVELOPER="${SEM_ALLOW_SHARED_DEVELOPER:-0}"
[[ "$SEM_ALLOW_SHARED_DEVELOPER" == 0 || "$SEM_ALLOW_SHARED_DEVELOPER" == 1 ]] || die 'SEM_ALLOW_SHARED_DEVELOPER must be 0 or 1.'
if [[ "${3:-}" == --allow-shared-developer && ( "$ACTION" == setup-docker || "$ACTION" == setup-ssh ) && $# == 3 ]]; then
    SEM_ALLOW_SHARED_DEVELOPER=1
elif [[ $# -gt 2 ]]; then
    die 'Unexpected arguments (use --allow-shared-developer with setup-docker/setup-ssh).'
fi
if [[ "$EUID" == 0 && ( "$ACTION" == create || "$ACTION" == recreate || "$ACTION" == setup-docker || "$ACTION" == setup-ssh ) ]]; then
    die 'Run as the regular rootless Podman owner, without sudo. The manager requests sudo only for host setup.'
fi

# Storage Configuration
# Override these to place environments on a dedicated Linux filesystem:
#   SEM_STORAGE_ROOT=/mnt/hdd2/secure-env-manager/environments
#   SEM_IMAGE_ROOT=/mnt/hdd2/secure-env-manager/images
# SEM_CONTAINER_IMAGE can point at a migrated/snapshotted container image.
SEM_STORAGE_ROOT="${SEM_STORAGE_ROOT:-/opt}"
SEM_IMAGE_ROOT="${SEM_IMAGE_ROOT:-/var/lib}"
SEM_CONTAINER_IMAGE="${SEM_CONTAINER_IMAGE:-ubuntu:24.04}"
WORK_DIR="${SEM_STORAGE_ROOT%/}/isolated_${BOX_NAME}"
IMG_FILE="${SEM_IMAGE_ROOT%/}/isolated_${BOX_NAME}.img"
MAPPER_NAME="iso_${BOX_NAME}"
IMG_SIZE="100G"

# User Configuration
INTERNAL_USER="developer"
HOST_USER="${SUDO_USER:-$(id -un)}"
HOST_HOME="$(getent passwd "$HOST_USER" | cut -d: -f6)"
[[ "$HOST_HOME" == /* && -d "$HOST_HOME" ]] || die 'Cannot resolve the Podman owner home.'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

function show_help() {
    echo "Usage: $0 [create|recreate|delete|mount|verify|setup-ssh|setup-docker] [env_name]"
    echo "       $0 migrate <env_name> <destination-root>"
    echo "       $0 export <env_name> <bundle.gpg> [--recipient <gpg-id>]"
    echo "       $0 import <bundle.gpg> <storage-root> [new-env-name]"
    echo "       $0 send <bundle.gpg> <ssh-destination>"
    echo "  create  : Build a development environment with a separate rootless Docker builder"
    echo "  recreate: Rebuild container keeping encrypted storage (Safe Mode)"
    echo "  delete  : Destroy the container and wipe storage (Nuclear Mode)"
    echo "  mount   : Remount the encrypted storage (Run this after reboot)"
    echo "  verify  : Verify host home protection is working correctly"
    echo "  setup-ssh: Configure key-only, on-demand SSH access for an existing environment"
    echo "  setup-docker: Provision and select a separate-user rootless Docker builder"
    echo "  setup-docker/setup-ssh accept --allow-shared-developer when cross-box sharing is intended"
}

function sem_allocate_ssh_port() {
    local preferred="${SEM_SSH_PORT:-}" candidate offset
    local existing="$HOST_HOME/.config/secure-env-manager/ssh/$BOX_NAME.env"
    if [[ -z "$preferred" && -r "$existing" ]]; then
        preferred="$(sed -n 's/^SEM_SSH_PORT=//p' "$existing" | head -n 1)"
    fi
    if [[ -n "$preferred" ]]; then
        [[ "$preferred" =~ ^[0-9]+$ && "$preferred" -ge 1024 && "$preferred" -le 65535 ]] || {
            echo "❌ SEM_SSH_PORT must be between 1024 and 65535." >&2
            return 1
        }
        printf '%s\n' "$preferred"
        return 0
    fi
    offset=$(( $(printf '%s' "$BOX_NAME" | cksum | awk '{print $1}') % 5000 ))
    candidate=$((22000 + offset))
    while ss -H -ltn "sport = :$candidate" 2>/dev/null | grep -q .; do
        candidate=$((candidate + 1))
        [[ "$candidate" -le 26999 ]] || candidate=22000
    done
    printf '%s\n' "$candidate"
}

function sem_install_ssh_proxy_runtime() {
    local config_root="$HOST_HOME/.config/secure-env-manager/ssh"
    local bin_dir="$HOST_HOME/.local/bin"
    local unit_dir="$HOST_HOME/.config/systemd/user"
    install -d -m 700 "$config_root" "$bin_dir"
    install -d -m 755 "$unit_dir"
    cat > "$bin_dir/sem-ssh-proxy" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
box="${1:-}"
[[ "$box" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "Invalid secure environment name" >&2; exit 64; }
# ProxyCommand callers may sanitize or replace the desktop session bus variables.
# Resolve the rootless Podman owner's real user-systemd bus explicitly.
runtime_dir="/run/user/$(id -u)"
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
config="$HOME/.config/secure-env-manager/ssh/$box.env"
[[ -r "$config" ]] || { echo "No SSH configuration for secure environment '$box'" >&2; exit 69; }
# shellcheck disable=SC1090
source "$config"
[[ "${SEM_BOX_NAME:-}" == "$box" && "${SEM_SSH_PORT:-}" =~ ^[0-9]+$ ]] || {
  echo "Invalid SSH metadata for '$box'" >&2
  exit 65
}
exec 9>"$HOME/.config/secure-env-manager/ssh/$box.lock"
flock 9
# The templated unit is intentionally RemainAfterExit: `start` is a no-op when
# the container was killed manually. Reconcile the real Podman state first so
# SSH demand wakes a stopped container instead of waiting on a dead port.
container_running="$(podman inspect --format '{{.State.Running}}' "$box" 2>/dev/null || true)"
if [[ "$container_running" != "true" ]]; then
  systemctl --user restart "sem-container@$box.service"
  # Refresh readiness against the container that was just started. Keeping the
  # pre-start false value would make on-demand SSH time out forever.
  container_running=true
fi
for _ in $(seq 1 90); do
  bridge_mode=''
  if nc -z 127.0.0.1 "$SEM_SSH_PORT" 2>/dev/null; then
    bridge_mode=host
  elif podman inspect --format '{{.State.Running}}' "$box" 2>/dev/null | grep -qx true \
      && podman exec "$box" nc -z 127.0.0.1 "$SEM_SSH_PORT" 2>/dev/null; then
    bridge_mode=container
  fi
  if [[ -n "$bridge_mode" ]]; then
    flock -u 9
    child_pid=''
    cleanup() {
      local rc=$?
      trap - EXIT INT TERM HUP
      if [[ -n "$child_pid" ]]; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
      fi
      exit "$rc"
    }
    trap cleanup EXIT INT TERM HUP
    if [[ "$bridge_mode" == host ]]; then
      nc 127.0.0.1 "$SEM_SSH_PORT" <&0 &
    else
      podman exec -i "$box" nc 127.0.0.1 "$SEM_SSH_PORT" <&0 &
    fi
    child_pid=$!
    wait "$child_pid"
    exit $?
  fi
  sleep 1
done
echo "Secure environment '$box' started, but SSH did not become ready on port $SEM_SSH_PORT" >&2
exit 70
EOF
    chmod 700 "$bin_dir/sem-ssh-proxy"
    cat > "$unit_dir/sem-container@.service" <<'EOF'
[Unit]
Description=On-demand secure Distrobox environment %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/podman start %i
ExecStop=/usr/bin/podman stop --time 30 %i
TimeoutStartSec=120
TimeoutStopSec=60

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    # Keep the rootless Podman/systemd user manager available after reboot,
    # before an interactive desktop login.  The proxy remains on-demand; this
    # only makes its user bus and container state reliable for jump SSH.
    if command -v loginctl >/dev/null 2>&1 && [[ "$(loginctl show-user "$HOST_USER" -p Linger --value 2>/dev/null || true)" != yes ]]; then
        sudo loginctl enable-linger "$HOST_USER"
    fi
}

function sem_write_ssh_config_block() {
    local alias="$1" port="$2" key_file="$3" use_proxy="${4:-yes}" jump_key="${5:-}"
    local ssh_config="$HOST_HOME/.ssh/config"
    local known_hosts="$HOST_HOME/.ssh/sem_worker_known_hosts"
    local begin="# BEGIN secure-env-manager:$BOX_NAME" end="# END secure-env-manager:$BOX_NAME"
    install -d -m 700 "$HOST_HOME/.ssh"
    touch "$ssh_config"
    chmod 600 "$ssh_config"
    sed -i "/^${begin}$/,/^${end}$/d" "$ssh_config"
    cat >> "$ssh_config" <<EOF
$begin
Host $alias
    HostName 127.0.0.1
    Port $port
    User $INTERNAL_USER
    IdentityFile $key_file
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile $known_hosts
    ConnectTimeout 120
    ServerAliveInterval 15
    ServerAliveCountMax 4
$end
EOF
    if [[ "$use_proxy" == yes ]]; then
        [[ -f "$jump_key" ]] || die 'Missing restricted jump identity; refusing human-host proxy fallback.'
        sed -i "/^$end/i\    ProxyCommand ssh -T -o BatchMode=yes -o IdentityAgent=none -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o HostKeyAlias=sem-$(hostname -s)-jump -o UserKnownHostsFile=$known_hosts -i $jump_key orca-jump@127.0.0.1 $BOX_NAME" "$ssh_config"
    fi
}

function sem_pin_worker_host_keys() {
    local port="$1" known_hosts="$HOST_HOME/.ssh/sem_worker_known_hosts" inner_key outer_key line
    inner_key="$(podman exec --user developer "$BOX_NAME" cat /etc/ssh/ssh_host_ed25519_key.pub)"
    outer_key="$(cat /etc/ssh/ssh_host_ed25519_key.pub)"
    [[ "$inner_key" == ssh-ed25519\ * && "$outer_key" == ssh-ed25519\ * ]] || die 'Expected trusted local Ed25519 server host keys.'
    touch "$known_hosts"
    chmod 600 "$known_hosts"
    # Do not erase old pins automatically if a container/host key changes.
    # OpenSSH will reject a conflicting key and require deliberate review.
    for line in "[127.0.0.1]:$port $inner_key" "sem-$(hostname -s)-jump $outer_key"; do
        grep -qxF "$line" "$known_hosts" || printf '%s\n' "$line" >> "$known_hosts"
    done
}

function setup_ssh_access() {
    local use_proxy="${1:-yes}"
    [[ $EUID -ne 0 ]] || {
        echo "❌ Run setup-ssh as the rootless Podman owner, not with sudo." >&2
        return 1
    }
    podman container exists "$BOX_NAME" || {
        echo "❌ Container '$BOX_NAME' does not exist." >&2
        return 1
    }
    command -v nc >/dev/null || {
        echo "❌ Host package 'netcat-openbsd' is required." >&2
        return 1
    }
    local port key_file public_key alias metadata_dir jump_key=''
    local -a stage_options=()
    port="$(sem_allocate_ssh_port)"
    key_file="$HOST_HOME/.ssh/sem_${BOX_NAME}_ed25519"
    if [[ "$BOX_NAME" == personal && -f "$HOST_HOME/.ssh/orca_personal_ed25519" ]]; then
        key_file="$HOST_HOME/.ssh/orca_personal_ed25519"
    fi
    if [[ ! -f "$key_file" ]]; then
        ssh-keygen -q -t ed25519 -N '' -C "secure-env-manager:$BOX_NAME" -f "$key_file"
    fi
    chmod 600 "$key_file"
    chmod 644 "$key_file.pub"
    public_key="$(cat "$key_file.pub")"

    echo "🔐 Installing key-only SSH in '$BOX_NAME' on 127.0.0.1:$port..."
    if ! distrobox enter "$BOX_NAME" -- sh -lc 'command -v sshd >/dev/null && command -v nc >/dev/null'; then
        if ! distrobox enter "$BOX_NAME" -- sudo env DEBIAN_FRONTEND=noninteractive apt-get update; then
            echo "⚠️  A configured package repository failed to update; attempting the cached package indexes." >&2
        fi
        if ! distrobox enter "$BOX_NAME" -- sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server netcat-openbsd; then
            distrobox enter "$BOX_NAME" -- sh -lc 'command -v sshd >/dev/null && command -v nc >/dev/null' || {
                echo "❌ OpenSSH or netcat installation failed in '$BOX_NAME'." >&2
                return 1
            }
            echo "⚠️  Package configuration reported an unrelated error; SSH dependencies are present, continuing." >&2
        fi
    fi
    distrobox enter "$BOX_NAME" -- sudo install -d -o "$INTERNAL_USER" -g "$INTERNAL_USER" -m 700 "/home/$INTERNAL_USER/.ssh"
    if ! distrobox enter "$BOX_NAME" -- sudo -u "$INTERNAL_USER" grep -qxF "$public_key" "/home/$INTERNAL_USER/.ssh/authorized_keys" 2>/dev/null; then
        printf '%s\n' "$public_key" | distrobox enter "$BOX_NAME" -- sudo tee -a "/home/$INTERNAL_USER/.ssh/authorized_keys" >/dev/null
    fi
    distrobox enter "$BOX_NAME" -- sudo chown "$INTERNAL_USER:$INTERNAL_USER" "/home/$INTERNAL_USER/.ssh/authorized_keys"
    distrobox enter "$BOX_NAME" -- sudo chmod 600 "/home/$INTERNAL_USER/.ssh/authorized_keys"
    distrobox enter "$BOX_NAME" -- sudo tee /etc/ssh/sshd_config.d/90-secure-env-manager.conf >/dev/null <<EOF
Port $port
ListenAddress 127.0.0.1
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers $INTERNAL_USER
X11Forwarding no
AllowTcpForwarding local
GatewayPorts no
EOF
    distrobox enter "$BOX_NAME" -- sudo ssh-keygen -A
    distrobox enter "$BOX_NAME" -- sudo systemctl enable ssh >/dev/null
    if distrobox enter "$BOX_NAME" -- sudo systemctl is-active --quiet ssh; then
        distrobox enter "$BOX_NAME" -- sudo systemctl reload ssh
    else
        distrobox enter "$BOX_NAME" -- sudo systemctl start ssh
    fi

    metadata_dir="$HOST_HOME/.config/secure-env-manager/ssh"
    install -d -m 700 "$metadata_dir"
    cat > "$metadata_dir/$BOX_NAME.env" <<EOF
SEM_BOX_NAME=$BOX_NAME
SEM_SSH_PORT=$port
EOF
    chmod 600 "$metadata_dir/$BOX_NAME.env"
    alias="sem-$(hostname -s)-$BOX_NAME"
    if [[ "$use_proxy" == yes ]]; then
        jump_key="$HOST_HOME/.ssh/sem_orca_jump_ed25519"
        if [[ ! -f "$jump_key" ]]; then
            ssh-keygen -q -t ed25519 -N '' -C 'secure-env-manager:restricted-jump' -f "$jump_key"
        fi
        chmod 600 "$jump_key"
        [[ "$SEM_ALLOW_SHARED_DEVELOPER" == 0 ]] || stage_options+=(--allow-shared-developer)
        sudo bash "$SCRIPT_DIR/harden-worker-access.sh" stage "$BOX_NAME" "$jump_key.pub" --ssh-port "$port" "${stage_options[@]}"
    fi
    sem_pin_worker_host_keys "$port"
    sem_write_ssh_config_block "$alias" "$port" "$key_file" "$use_proxy" "$jump_key"
    echo "✅ SSH ready: ssh $alias"
    if [[ "$use_proxy" == yes ]]; then
        echo "   Restricted jump: orca-jump (only the approved '$BOX_NAME' transport, no host shell/forwarding)."
        echo "   Remote ProxyCommand: ssh -T -o IdentitiesOnly=yes -i /path/to/restricted-jump-key orca-jump@$(hostname -s) $BOX_NAME"
        echo '   Copy/pin the host public key through a trusted channel on the remote client; never distribute the human host key.'
    fi
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

function setup_default_input_devices() {
    echo "🎤 Setting up default input devices inside container..."
    
    # Install PulseAudio utilities, ALSA plugins for PulseAudio redirection, and tools
    distrobox enter "$BOX_NAME" -- sudo apt-get install -y pulseaudio-utils alsa-utils libasound2-plugins > /dev/null 2>&1 || true
    
    # Create ALSA config to redirect all ALSA applications to PulseAudio
    # This is CRITICAL for apps like PyAudio that use ALSA directly
    echo "📝 Configuring ALSA to use PulseAudio backend..."
    cat << 'ASLACONF' | distrobox enter "$BOX_NAME" -- sudo tee /etc/asound.conf > /dev/null
# Redirect ALSA to PulseAudio
pcm.!default {
    type pulse
    fallback "sysdefault"
    hint {
        show on
        description "Default ALSA Output (PulseAudio Sound Server)"
    }
}

ctl.!default {
    type pulse
    fallback "sysdefault"
}

# For applications that specifically request "pulse"
pcm.pulse {
    type pulse
}

ctl.pulse {
    type pulse
}
ASLACONF
    
    # Also create user-level config for the developer user
    cat << 'ASLACONF' | distrobox enter "$BOX_NAME" -- sudo tee /home/$INTERNAL_USER/.asoundrc > /dev/null
# Redirect ALSA to PulseAudio (user config)
pcm.!default {
    type pulse
    fallback "sysdefault"
    hint {
        show on
        description "Default ALSA Output (PulseAudio Sound Server)"
    }
}

ctl.!default {
    type pulse
    fallback "sysdefault"
}

pcm.pulse {
    type pulse
}

ctl.pulse {
    type pulse
}
ASLACONF
    distrobox enter "$BOX_NAME" -- sudo chown $INTERNAL_USER:$INTERNAL_USER /home/$INTERNAL_USER/.asoundrc
    
    # Create a script to set default input devices at runtime
    cat << 'EOF' | distrobox enter "$BOX_NAME" -- sudo tee /usr/local/bin/setup-default-inputs > /dev/null
#!/bin/bash
# Script to configure default input devices (microphone, webcam)
# This runs during container startup or can be called manually

set -e

# Wait for PulseAudio to be ready
wait_for_pulse() {
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if pactl info >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
        attempt=$((attempt + 1))
    done
    echo "Warning: PulseAudio not ready after ${max_attempts} attempts"
    return 1
}

# Set default audio input (microphone/source)
set_default_audio_input() {
    if ! command -v pactl &>/dev/null; then
        echo "pactl not available, skipping audio input setup"
        return 1
    fi
    
    if ! wait_for_pulse; then
        return 1
    fi
    
    # Get list of available sources (input devices)
    echo "Available audio input devices:"
    pactl list sources short 2>/dev/null || true
    
    # Try to find and set a physical microphone as default
    # Priority: USB mic > Built-in mic > Any available source
    local default_source=""
    
    # Look for USB microphone first (usually better quality)
    default_source=$(pactl list sources short 2>/dev/null | grep -i "usb" | grep -v "monitor" | head -1 | awk '{print $2}')
    
    # If no USB mic, look for any non-monitor input source
    if [ -z "$default_source" ]; then
        default_source=$(pactl list sources short 2>/dev/null | grep -v "monitor" | head -1 | awk '{print $2}')
    fi
    
    # Set as default if found
    if [ -n "$default_source" ]; then
        pactl set-default-source "$default_source" 2>/dev/null && \
            echo "✅ Default audio input set to: $default_source" || \
            echo "⚠️  Failed to set default audio input"
    else
        echo "⚠️  No suitable audio input device found"
    fi
}

# Set default webcam (v4l2 device)
set_default_webcam() {
    # List available video devices
    if [ -d /dev ]; then
        echo "Available video devices:"
        ls -la /dev/video* 2>/dev/null || echo "No video devices found"
    fi
    
    # Check if v4l2-ctl is available for more detailed info
    if command -v v4l2-ctl &>/dev/null; then
        echo "Video device details:"
        for dev in /dev/video*; do
            if [ -e "$dev" ]; then
                echo "  $dev: $(v4l2-ctl --device=$dev --info 2>/dev/null | grep 'Card type' | cut -d: -f2 || echo 'unknown')"
            fi
        done
    fi
    
    # Set V4L2 default device via environment (for applications that use it)
    local default_video=""
    if [ -e /dev/video0 ]; then
        default_video="/dev/video0"
    elif ls /dev/video* 1>/dev/null 2>&1; then
        default_video=$(ls /dev/video* 2>/dev/null | head -1)
    fi
    
    if [ -n "$default_video" ]; then
        echo "✅ Default webcam available at: $default_video"
        # Export for applications
        export OPENCV_VIDEOIO_PRIORITY_V4L2=1
        export V4L2_DEVICE="$default_video"
    fi
}

# Main
echo "🔧 Configuring default input devices..."
set_default_audio_input
set_default_webcam
echo "✅ Input device configuration complete"
EOF

    distrobox enter "$BOX_NAME" -- sudo chmod +x /usr/local/bin/setup-default-inputs
    
    # Add to the developer user's profile so it runs on login
    cat << 'EOF' | distrobox enter "$BOX_NAME" -- sudo tee -a /home/$INTERNAL_USER/.zshrc > /dev/null

# Auto-configure default input devices on shell startup (runs silently)
[ -x /usr/local/bin/setup-default-inputs ] && /usr/local/bin/setup-default-inputs >/dev/null 2>&1 &
EOF

    echo "✅ Default input device configuration installed"
}

function verify_host_home_protection() {
    python3 "$SCRIPT_DIR/worker-access/verify-filesystem.py" "$BOX_NAME" "$HOST_HOME"
}

function sem_docker_socket_inside() {
    local scope="$1"
    [[ "$scope" =~ ^[a-z][a-z0-9_-]{0,21}$ ]] || return 64
    # Choose the private path even before provisioning: missing builder =
    # no Docker access, never an implicit fallback to the host-root proxy.
    printf '/run/host/run/sem-docker/%s/docker.sock\n' "$scope"
}

function setup_docker_proxy() {
    SEM_DOCKER_SOCKET_INSIDE="$(sem_docker_socket_inside "$BOX_NAME")"
    [[ -f "$SCRIPT_DIR/harden-worker-access.sh" ]] || die 'Missing rootless builder installer.'
    require_commands podman rootlesskit dockerd-rootless.sh dockerd newuidmap newgidmap slirp4netns socat mount findmnt curl
    if [[ ( "$ACTION" == create || "$ACTION" == recreate ) && -S /tmp/distrobox-docker.sock && ! -L /tmp/distrobox-docker.sock ]]; then
        die 'A legacy shared Docker proxy still exists. Audit/revoke it deliberately before creating more workers; this command will not stop it or disrupt its workloads. Existing boxes can use additive setup-docker first.'
    fi
    echo "🐳 Docker will use a separate locked host account at $SEM_DOCKER_SOCKET_INSIDE."
    echo '   Host-root Docker and shared legacy proxies are not created or modified.'
}

function sem_setup_rootless_docker() {
    local -a builder_options=()
    [[ "$SEM_ALLOW_SHARED_DEVELOPER" == 0 ]] || builder_options+=(--allow-shared-developer)
    setup_docker_proxy
    sudo bash "$SCRIPT_DIR/harden-worker-access.sh" docker "$BOX_NAME" "${builder_options[@]}" || return $?
    # Check the developer/client permission path, not only the daemon-owner API.
    podman exec --user developer "$BOX_NAME" curl --fail --silent --show-error --max-time 5 \
        --unix-socket "$SEM_DOCKER_SOCKET_INSIDE" http://localhost/_ping | grep -qx OK || die 'Developer cannot reach private Docker; profiles were not switched.'
    podman exec --user developer --env "DOCKER_HOST=unix://$SEM_DOCKER_SOCKET_INSIDE" "$BOX_NAME" \
        docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless' || die 'Selected Docker daemon is not rootless; profiles were not switched.'
    printf 'export DOCKER_HOST=%q\n' "unix://$SEM_DOCKER_SOCKET_INSIDE" | \
        distrobox enter "$BOX_NAME" -- sudo tee /etc/profile.d/docker-host.sh >/dev/null
    distrobox enter "$BOX_NAME" -- sudo chmod 644 /etc/profile.d/docker-host.sh
    distrobox enter "$BOX_NAME" -- sudo sh -c '
        developer_uid=$(id -u developer)
        line="if [ \"\$EUID\" = $developer_uid ] && [ -r /etc/profile.d/docker-host.sh ]; then . /etc/profile.d/docker-host.sh; fi"
        for file in /etc/zsh/zshenv /etc/zshenv; do
            [ -f "$file" ] || continue
            grep -qxF "$line" "$file" || sed -i "1i$line" "$file"
        done'
    distrobox enter "$BOX_NAME" -- sudo -H -u developer sh -c '
        for file in "$HOME/.zshenv" "$HOME/.bashrc"; do
            touch "$file"
            line="[ ! -r /etc/profile.d/docker-host.sh ] || . /etc/profile.d/docker-host.sh"
            grep -qxF "$line" "$file" || sed -i "1i$line" "$file"
        done'
    echo '✅ Private rootless Docker selected. Existing shells retain their exports until reopened.'
    echo '   Old rootful socket/proxy access is NOT automatically revoked; audit it separately before cloud connection.'
}

function install_bridge() {
    echo "bridge: Installing internal permission bridge..."
    
    # Install socat for audio socket proxying and ALSA plugins for PulseAudio redirect
    distrobox enter "$BOX_NAME" -- sudo apt-get install -y socat pulseaudio-utils libasound2-plugins > /dev/null 2>&1 || true
    # Transfer the single audio authentication cookie from the trusted host-side
    # installer. Never bind the host home merely so an in-container bridge can
    # retrieve it. Existing developer cookies are left unchanged when absent.
    if [[ -f "$HOST_HOME/.config/pulse/cookie" ]]; then
        distrobox enter "$BOX_NAME" -- sudo install -d -m 700 -o developer -g developer /home/developer/.config/pulse
        podman exec -i --user 0 "$BOX_NAME" sh -c '
            umask 077; tee /home/developer/.config/pulse/cookie >/dev/null
            chown developer:developer /home/developer/.config/pulse/cookie
        ' < "$HOST_HOME/.config/pulse/cookie"
    fi
    
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

# 2. The trusted installer transferred the pulse cookie into the isolated home.

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
    
    # --- SET DEFAULT INPUT DEVICES ---
    # Set default audio input (microphone) if pactl is available
    if command -v pactl &>/dev/null; then
        # Try USB mic first, then any non-monitor source
        DEFAULT_MIC=$(pactl list sources short 2>/dev/null | grep -i "usb" | grep -v "monitor" | head -1 | awk "{print \$2}")
        [ -z "$DEFAULT_MIC" ] && DEFAULT_MIC=$(pactl list sources short 2>/dev/null | grep -v "monitor" | head -1 | awk "{print \$2}")
        [ -n "$DEFAULT_MIC" ] && pactl set-default-source "$DEFAULT_MIC" 2>/dev/null || true
    fi
    
    # Set default video device for applications
    [ -e /dev/video0 ] && export V4L2_DEVICE="/dev/video0"
    export OPENCV_VIDEOIO_PRIORITY_V4L2=1
    
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

    # ENVIRONMENT (~/.local/bin after system paths; asdf shims prepend on top)
    export PATH="/opt/isolated_wrappers:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:$HOME/.local/bin:$PATH"
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

if [ "$ACTION" == "help" ]; then
    show_help
    exit 0

elif [ "$ACTION" == "setup-docker" ]; then
    sem_setup_rootless_docker
    exit $?

elif [ "$ACTION" == "setup-ssh" ]; then
    SETUP_JUMP_PROXY=""
    safe_read "   Set up jump-proxy/on-demand startup too? (Y/n): " SETUP_JUMP_PROXY
    if [[ "$SETUP_JUMP_PROXY" =~ ^[Nn]$ ]]; then
        setup_ssh_access no
    else
        setup_ssh_access yes
    fi
    exit $?

elif [ "$ACTION" == "verify" ]; then
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

elif [[ "$ACTION" == "create" || "$ACTION" == "recreate" ]]; then
    if [ "$ACTION" == "recreate" ]; then
        echo "♻️  RECREATING ROOTLESS ENVIRONMENT: $BOX_NAME (Preserving Data)"
    else
        echo "🏗️  CREATING ROOTLESS ENVIRONMENT: $BOX_NAME"
    fi
    echo ""
    
    # Check prerequisites/select the private path; create the builder only
    # after provisioning establishes the real developer namespace identity.
    setup_docker_proxy
    echo ""

    echo "🛡️  CONTAINER ISOLATION:"
    echo "   - Developer user will work in isolated /home/developer (persistent storage)"
    echo "   - Developer has NO sudo access inside the container"
    echo "   - NOTE: Distrobox mounts host home for integration (visible but separate from \$HOME)"
    echo ""
    
    # --- AUTO-CLEANUP CHECK ---
    if podman container exists "$BOX_NAME"; then
        if [ "$ACTION" == "create" ]; then
            die "Container '$BOX_NAME' already exists. Use setup-docker for additive setup, or deliberately use recreate during maintenance. Nothing was stopped or reprovisioned."
        elif [ "$ACTION" == "recreate" ]; then
            echo "🛑 Stopping old container for safe recreation..."
            distrobox stop "$BOX_NAME" --yes || true
            distrobox rm "$BOX_NAME" --force || true
        fi
    fi
    
    safe_read "   Set password for internal user 'developer': " USER_PASS true
    if [ -z "$USER_PASS" ]; then echo "❌ Password cannot be empty."; exit 1; fi

    safe_read "   Isolate network namespace? (y/N - allows container-only VPN but breaks localhost app sharing): " ISOLATE_NET
    UNSHARE_NET_FLAG=""
    if [[ "$ISOLATE_NET" =~ ^[Yy]$ ]]; then
        UNSHARE_NET_FLAG="--unshare-netns"
        echo "   -> Network will be isolated."
    else
        echo "   -> Network will be shared with the host (Default)."
    fi

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

    if [ "$ACTION" == "recreate" ] && [ -f "$IMG_FILE" ]; then
        echo "♻️  Skipping encryption setup to preserve existing volume data."
        if mount_encrypted; then
            ENCRYPTION_ENABLED=0
        else
            echo "❌ Error mounting existing volume."
            exit 1
        fi
    else
        # Call setup_encryption and capture return value
        # Return 0 = encryption enabled, Return 1 = no encryption
        # Use subshell to prevent set -e from exiting on return 1
        if setup_encryption; then
            ENCRYPTION_ENABLED=0
        else
            ENCRYPTION_ENABLED=1
        fi
    fi
    
    if ! podman container exists "$BOX_NAME"; then
        # Distrobox --home is not a security mask. Filter its automatically added
        # host-root/home/tmp mounts before Podman sees them. Preserve the existing
        # device/capability/desktop-integration policy rather than silently reducing it.
        
        echo "🛡️  Setting up host home protection..."
        echo "   Host home: $HOST_HOME (will NOT be mounted)"
        echo "   Container user home: $WORK_DIR/home → /home/$INTERNAL_USER"
        echo "   Security: explicit filesystem mounts; developer has no sudo"
        
        # Note: $WORK_DIR/home and $WORK_DIR/host_mask are already created by setup_encryption
        # Just verify they exist
        if [ ! -d "$WORK_DIR/home" ]; then
            echo "❌ ERROR: $WORK_DIR/home does not exist. Setup failed."
            exit 1
        fi
        
        # host_mask is only the container's administrative user's private home.
        # worker-access/sem-podman removes the actual host home and /run/host root
        # bind mounts, and adds narrow GUI/audio/Docker integration endpoints.
        
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
        # This filesystem boundary is not a complete hostile-code sandbox; desktop
        # hardware access, capabilities and integration remain deliberately enabled.
        #
        # NOTE: Removed --unshare-devsys as it prevents access to audio/video devices
        # Device access is controlled explicitly via --device flags instead

        # Always scope container hostname to env.host (e.g. university.skyron-notebook)
        HOST_HOSTNAME="$(hostname -s 2>/dev/null || hostname)"
        CONTAINER_HOSTNAME="${BOX_NAME}.${HOST_HOSTNAME}"
        if [ "$(printf '%s' "$CONTAINER_HOSTNAME" | wc -m)" -gt 64 ]; then
            echo "❌ Error: Container hostname '$CONTAINER_HOSTNAME' exceeds 64 characters."
            exit 1
        fi
        echo "   Container hostname: $CONTAINER_HOSTNAME"

        require_commands python3
        # Reserve the scoped socket DIRECTORY before creation; the separate
        # builder cannot be provisioned until developer's mapping exists. Binding
        # the directory (not its first socket inode) also survives daemon restarts.
        if [[ ! -d "/run/sem-docker/$BOX_NAME" ]]; then
            sudo install -d -m 0755 "/run/sem-docker/$BOX_NAME"
        fi
        SEM_HOST_HOME="$HOST_HOME" SEM_ISOLATED_HOME="$WORK_DIR/home" \
        SEM_MASK_HOME="$WORK_DIR/host_mask" SEM_SCOPE="$BOX_NAME" SEM_HOST_UID="$(id -u)" \
        PATH="$SCRIPT_DIR/worker-access/podman-bin:$PATH" DBX_CONTAINER_MANAGER=podman \
        distrobox create --name "$BOX_NAME" \
            --image "$SEM_CONTAINER_IMAGE" \
            --hostname "$CONTAINER_HOSTNAME" \
            --volume "$WORK_DIR/home:/home/$INTERNAL_USER" \
            --home "$WORK_DIR/host_mask" \
            --unshare-process \
            $UNSHARE_NET_FLAG \
            --init-hooks "rm -f /var/run/docker.sock 2>/dev/null; ln -s '$SEM_DOCKER_SOCKET_INSIDE' /var/run/docker.sock" \
            --additional-flags "--privileged=false --ipc=private --shm-size=4g --cap-drop=ALL --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE --cap-add=SETUID --cap-add=SETGID --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=FSETID --cap-add=KILL --cap-add=NET_BIND_SERVICE --cap-add=SETFCAP --cap-add=SETPCAP --cap-add=SYS_CHROOT --cap-add=NET_ADMIN --device /dev/net/tun $DEVICES $AUDIO_MOUNTS --volume /tmp/.X11-unix:/tmp/.X11-unix:ro" \
            --init --yes
        
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

# Never weaken AppArmor profiles during package provisioning.

echo ">>> Installing System & Compliance Packages..."
apt-get update && apt-get install -y curl git zsh wget unzip build-essential sudo \
    software-properties-common ca-certificates gnupg xdg-utils desktop-file-utils xauth \
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev \
    docker.io docker-compose-v2 iptables libsecret-1-0 gnome-keyring dbus-x11 acl \
    libx11-xcb1 libxss1 libasound2t64 libnss3 libatk-bridge2.0-0 libgtk-3-0t64 libgbm1 fonts-noto-color-emoji \
    clamav clamav-daemon unattended-upgrades xscreensaver \
    pulseaudio-utils alsa-utils libasound2-plugins

# --- ALSA-to-PulseAudio Configuration ---
# This is CRITICAL for applications (like PyAudio) that use ALSA directly
# It redirects all ALSA calls to PulseAudio backend
echo ">>> Configuring ALSA to use PulseAudio backend..."
cat > /etc/asound.conf << 'ALSACONF'
# Redirect ALSA to PulseAudio - fixes "cannot find card '0'" errors
pcm.!default {
    type pulse
    fallback "sysdefault"
    hint {
        show on
        description "Default ALSA Output (PulseAudio Sound Server)"
    }
}

ctl.!default {
    type pulse
    fallback "sysdefault"
}

# For applications that specifically request "pulse"
pcm.pulse {
    type pulse
}

ctl.pulse {
    type pulse
}
ALSACONF

# Enable Unattended Upgrades
echo 'Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}"; "${distro_id}:${distro_codename}-security"; };' > /etc/apt/apt.conf.d/50unattended-upgrades
service unattended-upgrades start || true

# Set up global Docker connection for all users in container
printf 'export DOCKER_HOST=%q\n' "unix://$SEM_DOCKER_SOCKET_INSIDE" > /etc/profile.d/docker-host.sh
chmod 644 /etc/profile.d/docker-host.sh

INTERNAL_USER="developer"

# SECURITY: Create developer user WITHOUT sudo or docker access
# - No sudo: separates developer execution from administrative provisioning
# - No docker: docker group grants root-equivalent access (HSV-003)
# For admin tasks, use: distrobox enter $BOX_NAME -- sudo <command>
# (which uses the host user's sudo, not container sudo)
if ! id "$INTERNAL_USER" &>/dev/null; then 
    useradd -m -s /usr/bin/zsh -G audio,video,plugdev "$INTERNAL_USER"
fi
# Imported images can retain old administrative group memberships. Apply the
# same developer policy to them; do not silently preserve root-Docker/sudo grants.
for unsafe_group in sudo wheel docker hostdocker; do
    if getent group "$unsafe_group" >/dev/null; then
        if [[ "$(id -g "$INTERNAL_USER")" == "$(getent group "$unsafe_group" | cut -d: -f3)" ]]; then
            echo 'ERROR: developer has an administrative primary group; review the imported image identity.' >&2
            exit 1
        fi
        gpasswd -d "$INTERNAL_USER" "$unsafe_group" >/dev/null 2>&1 || true
    fi
done
if [[ "$(id -u "$INTERNAL_USER")" == 0 ]] || sudo -l -U "$INTERNAL_USER" >/dev/null 2>&1; then
    echo 'ERROR: developer still has administrative sudo access; review image sudoers before continuing.' >&2
    exit 1
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
    distrobox enter "$BOX_NAME" -- sudo env "SEM_DOCKER_SOCKET_INSIDE=$SEM_DOCKER_SOCKET_INSIDE" /bin/bash /tmp/root.sh
    # Developer now exists; verify its mappings and provision separate Docker.
    sem_setup_rootless_docker
    
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
    echo '[ ! -r /etc/profile.d/docker-host.sh ] || . /etc/profile.d/docker-host.sh'
    echo '[ -z "$ZSH_VERSION" ] && exec /usr/bin/zsh -l'
} >> "$HOME/.bashrc"

# --- 1.5. ALSA-to-PulseAudio User Config ---
# Create user-level .asoundrc for applications that need ALSA
echo ">>> Configuring user ALSA to PulseAudio redirect..."
cat > "$HOME/.asoundrc" << 'ALSACONF'
# Redirect ALSA to PulseAudio (user config)
pcm.!default {
    type pulse
    fallback "sysdefault"
    hint {
        show on
        description "Default ALSA Output (PulseAudio Sound Server)"
    }
}

ctl.!default {
    type pulse
    fallback "sysdefault"
}

pcm.pulse {
    type pulse
}

ctl.pulse {
    type pulse
}
ALSACONF

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
    if [[ -d /dev/dri ]]; then
        sudo bash "$SCRIPT_DIR/worker-access/enable-gpu-access.sh" "$BOX_NAME" "$HOST_USER"
    fi
    setup_video_permissions
    setup_default_input_devices
    
    # Final verification
    echo ""
    echo "🔍 Performing final host home protection check..."
    if verify_host_home_protection; then
        echo ""
        echo "🎉 SUCCESS! Secure Environment '$BOX_NAME' created."
        echo "💡 Next step: Run './setup-apps.sh $BOX_NAME' to install applications and launchers."
        SETUP_SSH=""
        safe_read "   Set up key-only SSH access? (Y/n): " SETUP_SSH
        if [[ ! "$SETUP_SSH" =~ ^[Nn]$ ]]; then
            SETUP_JUMP_PROXY=""
            safe_read "   Set up jump-proxy SSH with on-demand container startup? (Y/n): " SETUP_JUMP_PROXY
            if [[ "$SETUP_JUMP_PROXY" =~ ^[Nn]$ ]]; then
                setup_ssh_access no
            else
                setup_ssh_access yes
            fi
        fi
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
