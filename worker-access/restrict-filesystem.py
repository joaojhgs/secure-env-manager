#!/usr/bin/env python3
"""Replace ONLY a stopped, backed-up box's mounts; retain its original for rollback.

Requires the manager's successful --keep-snapshot --leave-stopped export. Does
not prune, reinstall, change capabilities, touch Podman storage configuration,
or rewrite/chown developer homes. No other environment is stopped or changed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
policy = importlib.machinery.SourceFileLoader("sem_mount_policy", str(HERE / "sem-podman")).load_module()


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def inspect(box):
    return json.loads(subprocess.check_output(["podman", "inspect", box]))[0]


def prepare(data, image, host_home, target_name=None):
    mounts = {m["Destination"]: m for m in data["Mounts"]}
    scoped_home = mounts["/home/developer"]["Source"]
    mask = next(m["Source"] for m in data["Mounts"] if m["Destination"].endswith("/host_mask"))
    command = data["Config"]["CreateCommand"]
    # Use precisely the engine arguments originally used for this environment.
    args = command[command.index("create"):]
    entry = args.index("--entrypoint")
    args[entry + 2] = image
    for destination in ("/dev/pts", "/var/log/journal"):
        m = mounts[destination]
        for i, arg in enumerate(args[:entry]):
            if arg == "--volume" and args[i + 1] == destination:
                args[i + 1] = f'{m["Name"]}:{destination}'
    args = policy.filter_create(args, host_home, scoped_home, mask, target_name or data["Name"], str(os.getuid()))
    # This is an initialized snapshot with an existing compatibility home, not
    # a new user's empty home. Distrobox 1.7's DISTROBOX_HOST_HOME/skel branch
    # unconditionally chowns that entire tree at every startup. Disable only
    # that first-home import branch; keep normal init, devices and integration.
    entry = args.index("--entrypoint")
    args[entry:entry] = ["--env", "DISTROBOX_HOST_HOME="]
    return args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("box")
    parser.add_argument("backup", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--target-name", help="Return an offline-held source to this original environment name")
    opts = parser.parse_args()
    if os.getuid() == 0:
        parser.error("Run as the regular rootless Podman owner")
    target = opts.target_name or opts.box
    if target != opts.box and subprocess.run(["podman", "container", "exists", target], check=False).returncode == 0:
        parser.error("Target container name already exists; original stays untouched")
    backup = opts.backup.resolve(strict=True)
    if backup.stat().st_mode & 0o077 or backup.stat().st_uid != os.getuid():
        parser.error("Backup must be owned by you and inaccessible to other users")
    expected = Path(str(backup) + ".sha256").read_text().split()[0]
    digest = hashlib.file_digest(backup.open("rb"), "sha256").hexdigest()
    if digest != expected:
        parser.error("Backup checksum mismatch; original stays untouched")
    image = Path(str(backup) + ".snapshot").read_text().strip()
    run("podman", "image", "exists", image)
    old = inspect(opts.box)
    if old["State"]["Running"]:
        parser.error("Original must be stopped by a successful consistent export")
    try:
        args = prepare(old, image, os.path.expanduser("~"), target)
    except BaseException:
        if opts.apply:
            run("podman", "start", opts.box, stdout=subprocess.DEVNULL)
            print("Preparation refused; original container restarted unchanged.", file=sys.stderr)
        raise
    if not opts.apply:
        print("PASS: verified backup/snapshot and prepared mount-only replacement. Use --apply for cutover.")
        return 0
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rollback = f"{target}-hostfs-rollback-{stamp}"
    stage = f"{target}-hostfs-stage-{stamp}"
    name_index = args.index("--name")
    args[name_index + 1] = stage
    swapped = False
    try:
        # Reuse the original engine's global cgroup option too.
        original = old["Config"]["CreateCommand"]
        global_args = original[1:original.index("create")]
        run("podman", *global_args, *args, stdout=subprocess.DEVNULL)
        new = inspect(stage)
        for key in ("Privileged", "CapAdd", "CapDrop", "SecurityOpt", "NetworkMode", "PidMode", "IpcMode", "Devices", "ShmSize"):
            if new["HostConfig"].get(key) != old["HostConfig"].get(key):
                raise RuntimeError(f"Refusing unexpected change to hardware/privilege setting: {key}")
        run(sys.executable, str(HERE / "verify-filesystem.py"), stage, os.path.expanduser("~"))
        run("podman", "rename", opts.box, rollback)
        run("podman", "rename", stage, target)
        swapped = True
        run("podman", "start", target, stdout=subprocess.DEVNULL)
        ready = False
        entry_command = original[original.index("--entrypoint") + 3:]
        initful = "--init" in entry_command and entry_command[entry_command.index("--init") + 1] == "1"
        for _ in range(60):
            # .containerenv exists before Distrobox has finished initializing.
            # An initful snapshot is ready only after its actual init takes PID1.
            probe = ["sh", "-c", "test \"$(cat /proc/1/comm)\" = systemd"] if initful else ["test", "-f", "/run/.containerenv"]
            result = subprocess.run(["podman", "exec", target, *probe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError("Replacement did not start")
        if Path(f"/run/user/{os.getuid()}/pulse/native").exists():
            with (HERE / "configure-pulse-client.py").open("rb") as configuration:
                run("podman", "exec", "-i", "--user", "0", target,
                    "runuser", "-l", "developer", "-c", f"python3 - {os.getuid()}",
                    stdin=configuration)
        run(sys.executable, str(HERE / "verify-filesystem.py"), target, os.path.expanduser("~"))
        print(f"CUTOVER: {target}; stopped rollback container: {rollback}")
        print("Installed system, isolated home, original hardware privileges and private builders retained.")
    except BaseException:
        if swapped:
            subprocess.run(["podman", "stop", "--time", "10", target], check=False)
            run("podman", "rename", target, stage)
            run("podman", "rename", rollback, opts.box)
        elif subprocess.run(["podman", "container", "exists", rollback], check=False).returncode == 0:
            run("podman", "rename", rollback, opts.box)
        run("podman", "start", opts.box, stdout=subprocess.DEVNULL)
        print("Rolled back to the original container; no developer-home changes/deletion performed.", file=sys.stderr)
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
