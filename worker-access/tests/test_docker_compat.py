import importlib.util
from pathlib import Path
import socket
import threading
import unittest

spec = importlib.util.spec_from_file_location("compat", Path(__file__).parents[1] / "sem-docker-compat.py")
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)


class DockerCompatTests(unittest.TestCase):
    def config(self):
        return {"service_uid": 101000, "service_gid": 101001, "backends": [
            {"scope": scope, "container_id": marker * 64, "peer_uid": 101000,
             "socket": f"/run/sem-docker/{scope}/docker.sock"}
            for scope, marker in (("personal", "a"), ("university", "b"), ("work", "c"))]}

    def test_scope_selection(self):
        cfg = compat.validate_config(self.config())
        for scope, marker in (("personal", "a"), ("university", "b"), ("work", "c")):
            for prefix in ("libpod-", "libpod-conmon-"):
                groups = f"1:net_cls:/\n0::/user.slice/{prefix}{marker * 64}.scope/container\n"
                self.assertEqual(compat.choose_backend(cfg, 101000, groups), f"/run/sem-docker/{scope}/docker.sock")

    def test_unknown_ambiguous_wrong_uid(self):
        cfg = self.config()
        for uid, groups in ((1000, f"0::/libpod-{'a'*64}.scope"),
                            (0, f"0::/libpod-{'a'*64}.scope"),
                            (101000, "0::/user.slice"),
                            (101000, f"0::/libpod-{'a'*64}.scope/libpod-{'b'*64}.scope"),
                            (101000, f"0::/libpod-{'a'*64}.scope-fake")):
            with self.assertRaises(PermissionError):
                compat.choose_backend(cfg, uid, groups)

    def test_no_rootful_or_arbitrary_destination(self):
        for bad in ("/var/run/docker.sock", "/run/docker.sock", "tcp://localhost:2375", "/run/sem-docker/work/../docker.sock"):
            cfg = self.config()
            cfg["backends"][0]["socket"] = bad
            with self.assertRaises(ValueError):
                compat.validate_config(cfg)

    def test_identity_and_duplicate_guards(self):
        for name in ("service_uid", "service_gid"):
            cfg = self.config()
            cfg[name] = 0
            with self.assertRaises(ValueError):
                compat.validate_config(cfg)
        cfg = self.config()
        cfg["backends"][1]["container_id"] = cfg["backends"][0]["container_id"]
        with self.assertRaises(ValueError):
            compat.validate_config(cfg)

    def test_streaming_and_half_close(self):
        client, relay_client = socket.socketpair()
        relay_backend, backend = socket.socketpair()
        for item in (client, relay_client, relay_backend, backend):
            self.addCleanup(item.close)
            item.settimeout(3)
        relay = threading.Thread(target=compat.pipe_bytes, args=(relay_client, relay_backend))
        relay.start()
        client.sendall(b"docker-build-context")
        self.assertEqual(backend.recv(1024), b"docker-build-context")
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(backend.recv(1024), b"")
        backend.sendall(b"docker-build-response")
        backend.shutdown(socket.SHUT_WR)
        self.assertEqual(client.recv(1024), b"docker-build-response")
        self.assertEqual(client.recv(1024), b"")
        relay.join(3)
        self.assertFalse(relay.is_alive())


if __name__ == "__main__":
    unittest.main()
