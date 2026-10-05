#!/usr/bin/env python3
"""Configure the developer's narrow host-audio endpoint, never the host home."""
import os
from pathlib import Path
import pwd
import sys
import tempfile

MARKER = '# Managed by secure-env-manager: narrow host PulseAudio endpoint\n'


def configuration(host_uid):
    if not str(host_uid).isdigit() or int(host_uid) < 1:
        raise ValueError('Expected an unprivileged host UID')
    return MARKER + f'default-server = unix:/run/host/run/user/{int(host_uid)}/pulse/native\nautospawn = no\n'


def main():
    if len(sys.argv) != 2 or os.getuid() != pwd.getpwnam('developer').pw_uid:
        raise SystemExit('Run as developer with the host UID')
    content = configuration(sys.argv[1])
    target = Path('/home/developer/.config/pulse/client.conf')
    if target.is_symlink() or target.parent.is_symlink():
        raise SystemExit('Refusing a symlinked audio configuration')
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.exists():
        original = target.read_text()
        if original == content:
            print('PASS: narrow audio default already configured.')
            return
        if not original.startswith(MARKER):
            raise SystemExit('Custom PulseAudio client configuration retained; review its default-server manually')
        # Preserve other managed settings/comments if this is moved to another host.
        retained = [line for line in original.splitlines(True)
                    if not line.lstrip().startswith(('default-server', 'autospawn')) and line != MARKER]
        content += ''.join(retained)
    with tempfile.NamedTemporaryFile(mode='w', dir=target.parent, prefix='.sem-pulse-', delete=False) as output:
        temporary = Path(output.name)
        try:
            os.fchmod(output.fileno(), 0o600)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    print('PASS: default audio routes to the narrow host socket; private cookie retained.')


if __name__ == '__main__':
    main()
