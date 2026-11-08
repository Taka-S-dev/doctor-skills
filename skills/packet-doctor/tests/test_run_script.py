import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run.py"


class RunScriptTests(unittest.TestCase):
    def test_runs_from_another_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            done = subprocess.run([sys.executable, "-B", str(SCRIPT), "check-env"], cwd=folder, capture_output=True, encoding="utf-8")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["status"], "ok")


if __name__ == "__main__":
    unittest.main()
