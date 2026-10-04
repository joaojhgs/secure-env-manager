#!/usr/bin/env python3
"""Verify live mount definitions; never equate chmod 0700 with host isolation."""
import json
import os
import subprocess
import sys


def verify(box, host_home):
    data = json.loads(subprocess.check_output(["podman", "inspect", box]))[0]
    failures = []
    host_home = os.path.realpath(host_home)
    for mount in data["Mounts"]:
        if mount["Type"] != "bind":
            continue
        source = os.path.realpath(mount["Source"])
        if source in ("/", "/home", "/var/home", "/tmp", "/run", "/mnt", "/media", "/opt") or source == host_home or source.startswith(host_home + "/"):
            failures.append(f'{source} -> {mount["Destination"]}')
    if data["State"]["Running"]:
        probe = "import os,sys; sys.exit(any(os.path.exists(p) for p in sys.argv[1:]))"
        for user in ("developer", "0"):
            paths = [host_home + "/.ssh", "/run/host" + host_home + "/.ssh"]
            result = subprocess.run(["podman", "exec", "--user", user, box,
                                     "python3", "-c", probe, *paths], check=False)
            if result.returncode:
                failures.append(f"{user}: host SSH directory is present or probe failed")
    if failures:
        print("FAIL: host filesystem boundary: " + "; ".join(failures), file=sys.stderr)
        return 1
    print("PASS: no broad host filesystem/home binds; running root/developer probes passed when applicable.")
    return 0


if __name__ == "__main__":
    sys.exit(verify(*sys.argv[1:]))
