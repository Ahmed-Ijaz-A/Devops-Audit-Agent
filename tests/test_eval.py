import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))

from score import score

KEY = {"expected": [
    {"id": "hardcoded-key", "categories": ["security"], "file": "config.py", "lines": [4]},
    {"id": "missing-readme", "categories": ["repository_hygiene"], "file": None, "keywords": ["readme"]},
    {"id": "no-ci", "categories": ["ci_cd"], "file": None, "optional": True, "keywords": ["ci"]},
]}


def violation(category, file=None, line=None, description="problem"):
    return {"rule_id": "X-001", "category": category, "file": file, "line": line, "description": description, "evidence": ""}


class ScoreTests(unittest.TestCase):
    def test_counts_true_positives_duplicates_and_false_positives(self):
        result = score({"violations": [
            violation("security", "config.py", 5),
            violation("security", "config.py", 4),
            violation("repository_hygiene", description="No README file"),
            violation("testing", description="Something else"),
        ]}, KEY)
        self.assertEqual([row[0] for row in result["rows"]], ["TP", "duplicate", "TP", "FP"])
        self.assertEqual((result["tp"], result["counted"], result["known"]), (2, 4, 2))
        self.assertEqual(result["missed"], [])

    def test_line_far_from_expected_is_not_a_match(self):
        result = score({"violations": [violation("security", "config.py", 30)]}, KEY)
        self.assertEqual(result["rows"][0][0], "FP")
        self.assertEqual(result["missed"], ["hardcoded-key", "missing-readme"])

    def test_optional_defects_are_neutral(self):
        result = score({"violations": [violation("ci_cd", description="No CI workflow")]}, KEY)
        self.assertEqual(result["rows"][0][0], "optional")
        self.assertEqual((result["counted"], result["precision"], result["recall"]), (0, 1.0, 0.0))

    def test_keywords_disambiguate_repository_wide_findings(self):
        result = score({"violations": [violation("repository_hygiene", description="Missing .gitignore")]}, KEY)
        self.assertEqual(result["rows"][0][0], "FP")


if __name__ == "__main__":
    unittest.main()
