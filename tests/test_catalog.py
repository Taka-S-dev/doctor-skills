import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = sorted(path for path in (ROOT / "skills").iterdir() if path.is_dir())


class CatalogTests(unittest.TestCase):
    def test_every_skill_follows_the_format(self):
        self.assertTrue(SKILLS)
        for skill in SKILLS:
            text = (skill / "SKILL.md").read_text(encoding="utf-8")
            front = re.match(r"---\n(.*?)\n---\n", text, re.S).group(1)
            fields = dict(line.split(": ", 1) for line in front.splitlines())
            self.assertEqual(fields["name"], skill.name)
            self.assertRegex(fields["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$")
            self.assertLessEqual(len(fields["description"]), 1024)
            self.assertLessEqual(len(text.splitlines()), 500, skill.name)

    def test_every_skill_is_in_the_marketplace(self):
        catalog = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text(encoding="utf-8"))
        listed = {plugin["name"]: plugin["skills"] for plugin in catalog["plugins"]}
        self.assertEqual(listed, {skill.name: [f"./skills/{skill.name}"] for skill in SKILLS})

    def test_readme_lists_every_skill(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for skill in SKILLS:
            self.assertIn(f"skills/{skill.name}", readme)


if __name__ == "__main__":
    unittest.main()
