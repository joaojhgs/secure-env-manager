#!/usr/bin/env bash
set -Eeuo pipefail

SUPPORTED_BUNDLE_VERSION=1
SEM_CLEANUP_STAGING=""
SEM_CLEANUP_OUTPUT_TMP=""
SEM_CLEANUP_IMAGE=""
SEM_CLEANUP_BOX=""
SEM_CLEANUP_RESTART=false

cleanup_export() {
    if [[ "$SEM_CLEANUP_RESTART" == true && -n "$SEM_CLEANUP_BOX" ]]; then
        # A cancelled podman commit/save can leave the overlay mount attached.
        podman unmount "$SEM_CLEANUP_BOX" >/dev/null 2>&1 || true
        podman start "$SEM_CLEANUP_BOX" >/dev/null 2>&1 || true
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
  ./transfer-environment.sh export <box> <bundle.gpg> [--recipient <gpg-id>]
  ./transfer-environment.sh import <bundle.gpg> <storage-root> [new-box-name]
  ./transfer-environment.sh send <bundle.gpg> <ssh-destination>

Examples:
  # Password-encrypted bundle (GPG prompts for the password)
  ./transfer-environment.sh export personal /mnt/backup/personal.sem.tar.gpg

  # Encrypt to a GPG public key instead
  ./transfer-environment.sh export personal personal.sem.tar.gpg \
      --recipient user@example.com

  # Copy the encrypted bundle and checksum over SSH
  ./transfer-environment.sh send personal.sem.tar.gpg user@new-pc:/srv/transfers/

  # On the destination computer
  ./transfer-environment.sh import personal.sem.tar.gpg \
      /mnt/hdd3/secure-env-manager personal

The bundle contains a portable OCI image, the isolated developer home with
container-relative ownership/ACLs/xattrs, the source container definition, a
manifest, and checksums. Import never deletes an existing container or home.
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
    local box="$1" output="$2" recipient=""
    shift 2
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --recipient)
                [[ $# -ge 2 ]] || die "--recipient requires a GPG identity"
                recipient="$2"
                shift 2
                ;;
            *) die "unknown export option: $1" ;;
        esac
    done

    require_commands podman distrobox gpg tar zstd sha256sum mktemp
    [[ $EUID -ne 0 ]] || die "run as the regular rootless Podman user, not root"
    podman container exists "$box" || die "container not found: $box"
    [[ ! -e "$output" ]] || die "output already exists: $output"
    mkdir -p "$(dirname "$output")"

    local staging stamp image source_home was_running=false developer_uid developer_gid owner_pair
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
    owner_pair="$(podman unshare stat -c '%u:%g' "$source_home")"
    developer_uid="${owner_pair%%:*}"
    developer_gid="${owner_pair##*:}"

    if [[ "$(podman inspect "$box" --format '{{.State.Running}}')" == true ]]; then
        was_running=true
        SEM_CLEANUP_RESTART=true
        echo "Stopping $box for a consistent export..."
        distrobox stop "$box" --yes
    fi
    echo "Creating OCI image snapshot..."
    podman commit "$box" "$image" >/dev/null
    podman save --format oci-archive -o "$staging/rootfs.oci.tar" "$image"

    echo "Archiving developer home with container-relative ownership..."
    podman unshare tar --acls --xattrs --numeric-owner --sparse -cpf - \
        -C "$source_home" . | zstd -T0 -3 -o "$staging/developer-home.tar.zst"

    podman inspect "$box" > "$staging/container-inspect.json"
    cat > "$staging/manifest.env" <<EOF
BUNDLE_VERSION=$SUPPORTED_BUNDLE_VERSION
BOX_NAME=$box
CREATED_UTC=$stamp
IMAGE_REF=$image
HOME_DESTINATION=/home/developer
DEVELOPER_UID=$developer_uid
DEVELOPER_GID=$developer_gid
SOURCE_HOME=$source_home
EOF
    (cd "$staging" && sha256sum rootfs.oci.tar developer-home.tar.zst container-inspect.json manifest.env > SHA256SUMS)

    echo "Encrypting transfer bundle..."
    if [[ -n "$recipient" ]]; then
        tar -C "$staging" -cpf - manifest.env SHA256SUMS rootfs.oci.tar developer-home.tar.zst container-inspect.json |
            gpg --batch --yes --encrypt --recipient "$recipient" --output "$output.tmp"
    else
        tar -C "$staging" -cpf - manifest.env SHA256SUMS rootfs.oci.tar developer-home.tar.zst container-inspect.json |
            gpg --symmetric --cipher-algo AES256 --compress-algo none --output "$output.tmp"
    fi
    mv "$output.tmp" "$output"
    (cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
    chmod 600 "$output" "$output.sha256"
    echo "Bundle: $output"
    echo "Checksum: $output.sha256"
}

import_bundle() {
    [[ $# -ge 2 && $# -le 3 ]] || { usage >&2; exit 2; }
    local bundle="$1" storage_root="${2%/}" requested_name="${3:-}"
    require_commands podman gpg tar zstd sha256sum mktemp findmnt sudo
    [[ $EUID -ne 0 ]] || die "run as the regular rootless Podman user, not root"
    [[ -f "$bundle" ]] || die "bundle not found: $bundle"
    if [[ -f "$bundle.sha256" ]]; then
        (cd "$(dirname "$bundle")" && sha256sum -c "$(basename "$bundle").sha256")
    fi
    verify_linux_destination "$storage_root"

    local staging box image developer_uid developer_gid env_root dest_home dest_mask
    staging="$(mktemp -d)"
    SEM_CLEANUP_STAGING="$staging"
    trap cleanup_import EXIT
    trap 'exit 130' INT TERM HUP
    echo "Decrypting bundle..."
    gpg --decrypt "$bundle" | tar -xpf - -C "$staging"
    [[ -f "$staging/manifest.env" && -f "$staging/SHA256SUMS" ]] || die "invalid transfer bundle"
    (cd "$staging" && sha256sum -c SHA256SUMS)

    local bundle_version source_box
    bundle_version="$(sed -n 's/^BUNDLE_VERSION=//p' "$staging/manifest.env")"
    source_box="$(sed -n 's/^BOX_NAME=//p' "$staging/manifest.env")"
    image="$(sed -n 's/^IMAGE_REF=//p' "$staging/manifest.env")"
    developer_uid="$(sed -n 's/^DEVELOPER_UID=//p' "$staging/manifest.env")"
    developer_gid="$(sed -n 's/^DEVELOPER_GID=//p' "$staging/manifest.env")"
    [[ "$bundle_version" == "$SUPPORTED_BUNDLE_VERSION" ]] || die "unsupported bundle version: ${bundle_version:-missing}"
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
    zstd -dc "$staging/developer-home.tar.zst" |
        podman unshare tar --acls --xattrs --same-owner --sparse -xpf - -C "$dest_home"
    podman unshare chown "$developer_uid:$developer_gid" "$dest_home"

    echo "Loading OCI image..."
    podman load -i "$staging/rootfs.oci.tar"
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

case "${1:-}" in
    export) shift; export_bundle "$@" ;;
    import) shift; import_bundle "$@" ;;
    send) shift; send_bundle "$@" ;;
    help|-h|--help|"") usage ;;
    *) usage >&2; die "unknown command: $1" ;;
esac
