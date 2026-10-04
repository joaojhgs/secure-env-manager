#!/usr/bin/env python3
"""Temporary metadata-only probe; run through the owner's podman unshare.

Never opens Docker sockets. Drops all namespace capabilities by changing UID
before accepting real developer peers. Removes only its own test socket.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys


def main():
    module_path, directory, *pairs = sys.argv[1:]
    spec = importlib.util.spec_from_file_location("compat", module_path)
    compat = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compat)
    config = compat.validate_config({
        "service_uid": 1001,
        "service_gid": 1002,
        "backends": [{"scope": scope, "container_id": ident, "peer_uid": 1001,
                      "socket": f"/run/sem-docker/{scope}/docker.sock"}
                     for scope, ident in zip(pairs[::2], pairs[1::2])],
    })
    os.chown(directory, 1001, 1002)
    os.chmod(directory, 0o755)
    os.setgroups([])
    os.setgid(1002)
    os.setuid(1001)
    endpoint = str(Path(directory) / "peer.sock")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(endpoint)
            os.chmod(endpoint, 0o666)  # Permit the negative host-identity test.
            listener.listen(4)
            listener.settimeout(45)
            print("READY metadata-only peer probe", flush=True)
            for _ in range(4):
                client, _ = listener.accept()
                with client:
                    try:
                        backend = compat.peer_backend(client, config)
                        result = backend.split("/")[-2]
                    except (OSError, PermissionError):
                        result = "DENIED"
                    client.sendall((result + "\n").encode("ascii"))
                    print(json.dumps({"route": result}), flush=True)
    finally:
        if os.path.lexists(endpoint):
            os.unlink(endpoint)


if __name__ == "__main__":
    main()
