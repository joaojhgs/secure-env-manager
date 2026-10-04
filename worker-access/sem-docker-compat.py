#!/usr/bin/env python3
"""Unix byte relay: an approved Podman peer maps only to its rootless builder.

No Docker HTTP parsing, rootful backend, arbitrary destination or elevated UID.
The legacy shared path is retained for running clients; SO_PEERCRED and the
peer's host-visible cgroup choose the configured environment.
"""
import json
import os
import re
import selectors
import socket
import stat
import struct
import threading

CONFIG = "/etc/sem-worker-access/docker-compat.json"
SCOPE = re.compile(r"[a-z][a-z0-9_-]{0,21}\Z")
CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
CGROUP_ID = re.compile(r"(?:libpod|libpod-conmon)-([0-9a-f]{64})\.scope(?:/|$)")


def validate_config(config):
    if set(config) != {"service_uid", "service_gid", "backends"}:
        raise ValueError("invalid configuration fields")
    for name in ("service_uid", "service_gid"):
        if type(config[name]) is not int or config[name] < 1:
            raise ValueError("service must be an unprivileged numeric identity")
    backends = config["backends"]
    if not isinstance(backends, list) or not 1 <= len(backends) <= 16:
        raise ValueError("invalid backend count")
    seen = set()
    for backend in backends:
        if set(backend) != {"scope", "container_id", "peer_uid", "socket"}:
            raise ValueError("invalid backend fields")
        scope = backend["scope"]
        if not isinstance(scope, str) or not SCOPE.fullmatch(scope):
            raise ValueError("invalid scope")
        ident = backend["container_id"]
        if not isinstance(ident, str) or not CONTAINER.fullmatch(ident) or ident in seen:
            raise ValueError("invalid/duplicate container ID")
        if backend["socket"] != f"/run/sem-docker/{scope}/docker.sock":
            raise ValueError("backend is not a fixed private builder socket")
        if type(backend["peer_uid"]) is not int or backend["peer_uid"] != config["service_uid"]:
            raise ValueError("this compatibility relay requires deliberate shared identities")
        seen.add(ident)
    return config


def load_config(path=CONFIG):
    for checked, mode in ((os.path.dirname(path), 0o755), (path, 0o644)):
        info = os.stat(checked, follow_symlinks=False)
        if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode:
            raise PermissionError("configuration must be root-controlled")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "r", encoding="utf-8") as source:
        data = source.read(16385)
    if len(data) > 16384:
        raise ValueError("configuration too large")
    return validate_config(json.loads(data))


def choose_backend(config, peer_uid, cgroups):
    identifiers = set()
    for line in cgroups.splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3:
            identifiers.update(CGROUP_ID.findall(fields[2]))
    matches = [item for item in config["backends"]
               if item["peer_uid"] == peer_uid and item["container_id"] in identifiers]
    if len(matches) != 1:
        raise PermissionError("peer is not in exactly one approved environment")
    return matches[0]["socket"]


def peer_backend(client, config):
    pid, uid, _ = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if pid < 1 or uid != config["service_uid"]:
        raise PermissionError("unexpected peer identity")
    # Host-visible /proc is intentional. Never resolve peer paths supplied by
    # clients, and do not read credentials, cmdlines, environments or file data.
    with open(f"/proc/{pid}/cgroup", encoding="ascii") as source:
        groups = source.read(16385)
    if len(groups) > 16384:
        raise PermissionError("cgroup metadata too large")
    return choose_backend(config, uid, groups)


def pipe_bytes(client, upstream):
    selector = selectors.DefaultSelector()
    try:
        selector.register(client, selectors.EVENT_READ, upstream)
        selector.register(upstream, selectors.EVENT_READ, client)
        while selector.get_map():
            for event, _ in selector.select():
                source, destination = event.fileobj, event.data
                chunk = source.recv(65536)
                if chunk:
                    destination.sendall(chunk)
                else:
                    selector.unregister(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
    finally:
        selector.close()


def serve(listener, config, resolve=peer_backend):
    slots = threading.BoundedSemaphore(32)

    def handle(client):
        try:
            with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                upstream.connect(resolve(client, config))
                pipe_bytes(client, upstream)
        except (OSError, PermissionError):
            # Close on mismatch/missing builder. No fallback and no payload logs.
            pass
        finally:
            slots.release()

    while True:
        client, _ = listener.accept()
        if not slots.acquire(blocking=False):
            client.close()
            continue
        threading.Thread(target=handle, args=(client,), daemon=True).start()


def main():
    config = load_config()
    if os.getuid() != config["service_uid"] or os.getgid() != config["service_gid"]:
        raise PermissionError("wrong service identity; root/human-host execution is refused")
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("requires one systemd-activated Unix socket")
    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM:
        raise RuntimeError("unexpected activation socket")
    serve(listener, config)


if __name__ == "__main__":
    main()
