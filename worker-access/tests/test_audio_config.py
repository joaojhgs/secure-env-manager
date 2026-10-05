import importlib.machinery
from pathlib import Path
import unittest

audio = importlib.machinery.SourceFileLoader(
    'sem_audio', str(Path(__file__).resolve().parents[1] / 'configure-pulse-client.py')).load_module()


class AudioConfigTest(unittest.TestCase):
    def test_narrow_audio_default_and_no_host_home(self):
        text = audio.configuration('1000')
        self.assertIn('unix:/run/host/run/user/1000/pulse/native', text)
        self.assertIn('autospawn = no', text)
        self.assertNotIn('/home/', text)

    def test_alternate_host_uid(self):
        self.assertIn('/run/user/1002/pulse/native', audio.configuration('1002'))

    def test_invalid_uids_refused(self):
        for uid in ('0', '-1', 'x', '1000\nother-setting=yes'):
            with self.assertRaises(ValueError):
                audio.configuration(uid)
