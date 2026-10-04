#!/usr/bin/env python3
"""Exercise real tar/zstd/GPG backup paths with fake engines; never stop a real box."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

MANAGER = Path(__file__).resolve().parents[2] / "manage-safe-environement.sh"


class TransferBundleTest(unittest.TestCase):
    def test_compressed_export_restore_and_failure_restart(self):
        self.exercise_bundle(False)

    def test_streamed_home_export_restore_and_failure_restart(self):
        self.exercise_bundle(True)

    def exercise_bundle(self, stream_home):
        with tempfile.TemporaryDirectory(prefix="sem-backup-test-", dir=Path.home()) as tmp:
            root = Path(tmp)
            tools = root / "bin"
            tools.mkdir()
            home = root / "fixture-home"
            home.mkdir()
            (home / "source.txt").write_text("synthetic preserved source\n")
            (home / "source.txt").chmod(0o600)
            (home / "source-link").symlink_to("./source.txt")
            os.link(home / "source.txt", home / "source-hardlink")
            (home / "cache.bin").write_text("synthetic excluded cache\n")
            mask = root / "host_mask"
            mask.mkdir()
            (mask / "administrative-config").write_text("synthetic preserved compatibility settings\n")
            (mask / "administrative-config").chmod(0o600)
            volume = root / "journal-data"
            volume.mkdir()
            (volume / "persistent-state").write_text("synthetic persistent volume contents\n")
            (tools / "podman").write_text('''#!/bin/bash
set -e
printf '%s\\n' "$*" >> "$SEM_TEST_LOG"
case "$1" in
 container) exit 0 ;;
 inspect)
  if [[ "$*" == *State.Running* ]]; then echo true
  elif [[ "$*" == *Source* ]]; then echo "$SEM_TEST_HOME"
  else printf '%s\\n' "$SEM_TEST_INSPECT_JSON"; fi ;;
 unshare) shift; exec "$@" ;;
 commit) echo synthetic-image ;;
 save) printf 'synthetic OCI bytes\\n' ;;
 load) while IFS= read -r line; do :; done ;;
 image) exit 0 ;;
 start|unmount) exit 0 ;;
 *) exit 65 ;;
esac
''')
            (tools / "distrobox").write_text('#!/bin/bash\nprintf "distrobox %s\\n" "$*" >> "$SEM_TEST_LOG"\n')
            (tools / "sudo").write_text('#!/bin/bash\n[[ "$1" != -v ]] || exit 0\nexec "$@"\n')
            for tool in tools.iterdir():
                tool.chmod(0o755)
            passphrase = root / "recovery-key"
            passphrase.write_text("synthetic-testing-key-not-a-real-credential\n")
            passphrase.chmod(0o600)
            exclusions = root / "exclude.txt"
            exclusions.write_text("./cache.bin\n")
            env = dict(os.environ, PATH=str(tools) + ":" + os.environ["PATH"],
                       SEM_TEST_LOG=str(root / "calls"), SEM_TEST_HOME=str(home),
                       SEM_TEST_INSPECT_JSON=json.dumps([{"Name": "fixture", "Mounts": [
                           {"Type": "bind", "Source": str(home), "Destination": "/home/developer"},
                           {"Type": "bind", "Source": str(mask), "Destination": "/private/host_mask"},
                           {"Type": "volume", "Source": str(volume), "Destination": "/var/log/journal", "Name": "fixture-volume"}]}]),
                       GNUPGHOME=str(root / "gpg"))
            (root / "gpg").mkdir(mode=0o700)
            bundle = root / "fixture.gpg"
            command = ["bash", str(MANAGER), "export", "fixture", str(bundle),
                       "--passphrase-file", str(passphrase), "--exclude-file", str(exclusions),
                       "--keep-snapshot", "--leave-stopped"]
            if stream_home:
                command.append("--stream-home")
            subprocess.run(command, env=env, check=True, capture_output=True)
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o600)
            expected = Path(str(bundle) + ".sha256").read_text().split()[0]
            self.assertEqual(hashlib.sha256(bundle.read_bytes()).hexdigest(), expected)
            decrypted = subprocess.check_output(["gpg", "--batch", "--pinentry-mode", "loopback",
                                               "--passphrase-file", str(passphrase), "--decrypt", str(bundle)],
                                              env=env, stderr=subprocess.DEVNULL)
            archive = root / "bundle.tar"
            archive.write_bytes(subprocess.check_output(["zstd", "-dfc"], input=decrypted))
            unpack = root / "unpack"
            unpack.mkdir()
            with tarfile.open(archive) as tar:
                if stream_home:
                    self.assertNotIn(".", tar.getnames())
                    self.assertIn("home", tar.getnames())
                    self.assertEqual(tar.getmember("home/source-link").linkname, "./source.txt")
                    self.assertEqual(tar.getmember("home/source.txt").mode, 0o600)
                tar.extractall(unpack, filter="data")
            subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=unpack, check=True, capture_output=True)
            decoded = subprocess.check_output(["zstd", "-dc", str(unpack / "rootfs.oci.tar.zst")])
            self.assertEqual(decoded, b"synthetic OCI bytes\n")
            for filename, member, expected in [
                ("administrative-home.tar.zst", "./administrative-config", (mask / "administrative-config").read_bytes()),
                ("persistent-volume-0.tar.zst", "./persistent-state", (volume / "persistent-state").read_bytes()),
            ]:
                decoded_tar = root / "auxiliary.tar"
                decoded_tar.write_bytes(subprocess.check_output(["zstd", "-dc", str(unpack / filename)]))
                with tarfile.open(decoded_tar) as auxiliary:
                    self.assertEqual(auxiliary.extractfile(member).read(), expected)
                    if filename == "administrative-home.tar.zst":
                        self.assertEqual(auxiliary.getmember(member).mode, 0o600)
            restored = root / "restored"
            restored.mkdir()
            if stream_home:
                self.assertFalse((unpack / "home/cache.bin").exists())
                (restored / "source.txt").write_bytes((unpack / "home/source.txt").read_bytes())
            else:
                home_tar = root / "home.tar"
                home_tar.write_bytes(subprocess.check_output(["zstd", "-dc", str(unpack / "developer-home.tar.zst")]))
                with tarfile.open(home_tar) as tar:
                    self.assertIn("./source.txt", tar.getnames())
                    self.assertNotIn("./cache.bin", tar.getnames())
                    tar.extractall(restored, filter="data")
            log = (root / "calls").read_text()
            self.assertIn("distrobox stop fixture --yes", log)
            self.assertNotIn("start fixture", log)
            self.assertNotIn("image rm", log)
            # Exercise actual archived-home extraction without opening a PIN
            # dialog or touching the real Podman store.
            self.assertEqual((restored / "source.txt").read_text(), (home / "source.txt").read_text())
            # A failed save must restart the original and never hand off cutover.
            script = tools / "podman"
            script.write_text(script.read_text().replace("save) printf", "save) exit 42; printf"))
            fail_command = command.copy()
            fail_command[4] = str(root / "failed.gpg")
            failed = subprocess.run(fail_command,
                                    env=env, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("start fixture", (root / "calls").read_text())
            self.assertFalse((root / "failed.gpg").exists())


if __name__ == "__main__":
    unittest.main()
