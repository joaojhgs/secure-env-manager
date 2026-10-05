#!/usr/bin/env python3
import importlib.machinery
from pathlib import Path
import unittest
from unittest.mock import patch

policy = importlib.machinery.SourceFileLoader(
    "sem_podman", str(Path(__file__).resolve().parents[1] / "sem-podman")).load_module()
restriction = importlib.machinery.SourceFileLoader(
    "sem_restriction", str(Path(__file__).resolve().parents[1] / "restrict-filesystem.py")).load_module()


class MountPolicyTest(unittest.TestCase):
    def filtered(self, args):
        with patch.object(policy, "integration_mounts", return_value=[]):
            return policy.filter_create(args, "/home/human", "/opt/isolated_test/home",
                                        "/opt/isolated_test/host_mask", "test", "1000")

    def test_host_routes_removed_but_devices_and_caps_preserved(self):
        original = ["create", "--volume", "/:/run/host:rslave", "--volume=/home/human:/home/human",
                    "-v", "/tmp:/tmp", "--volume", "/dev:/dev:rslave", "--volume", "/sys:/sys:rslave",
                    "--volume", "/opt/isolated_test/home:/home/developer", "--cap-add=SYS_ADMIN",
                    "--device", "/dev/dri", "--privileged=false", "--entrypoint", "/usr/bin/entrypoint",
                    "ubuntu", "--home", "/opt/isolated_test/host_mask"]
        result = self.filtered(original)
        self.assertNotIn("/:/run/host:rslave", result)
        self.assertNotIn("--volume=/home/human:/home/human", result)
        self.assertNotIn("/tmp:/tmp", result)
        for value in ["/dev:/dev:rslave", "/sys:/sys:rslave", "--cap-add=SYS_ADMIN",
                      "--device", "/dev/dri", "--privileged=false"]:
            self.assertIn(value, result)
        self.assertEqual(result[result.index("--entrypoint"):], original[original.index("--entrypoint"):])

    def test_unexpected_binds_fail_closed(self):
        for value in ["/home/other:/data", "/var/run/docker.sock:/docker.sock", "/mnt:/mnt"]:
            with self.assertRaises(ValueError):
                self.filtered(["create", "--volume", value])

    def test_other_mount_syntax_cannot_bypass(self):
        for args in [["create", "--mount", "type=bind,source=/,destination=/host"],
                     ["create", "--volumes-from", "old"]]:
            with self.assertRaises(ValueError):
                self.filtered(args)

    def test_named_and_anonymous_volumes(self):
        self.assertIn("/dev/pts", self.filtered(["create", "-v", "/dev/pts"]))
        with self.assertRaises(ValueError):
            self.filtered(["create", "-v", "other-project:/data"])

    def test_offline_hold_keeps_original_integration_scope_and_volumes(self):
        data = {"Name": "personal-offline", "Mounts": [
            {"Destination": "/home/developer", "Source": "/opt/isolated/home"},
            {"Destination": "/opt/isolated/host_mask", "Source": "/opt/isolated/host_mask"},
            {"Destination": "/dev/pts", "Name": "a"*64},
            {"Destination": "/var/log/journal", "Name": "b"*64},
        ], "Config": {"CreateCommand": ["podman", "--cgroup-manager=cgroupfs", "create",
            "--name", "personal", "--volume", "/opt/isolated/home:/home/developer",
            "--volume", "/opt/isolated/host_mask:/opt/isolated/host_mask", "--volume", "/dev/pts",
            "--volume", "/var/log/journal", "--entrypoint", "/usr/bin/entrypoint", "old-image"]}}
        with patch.object(restriction.policy, "integration_mounts", return_value=[]) as integrations:
            result = restriction.prepare(data, "snapshot", "/home/human", "personal")
        integrations.assert_called_once_with("personal", str(restriction.os.getuid()))
        self.assertIn("a"*64+":/dev/pts", result)
        self.assertIn("b"*64+":/var/log/journal", result)
        self.assertIn("DISTROBOX_HOST_HOME=", result)
        self.assertLess(result.index("DISTROBOX_HOST_HOME="), result.index("--entrypoint"))
        self.assertEqual(result[-1], "snapshot")


if __name__ == "__main__":
    unittest.main()
