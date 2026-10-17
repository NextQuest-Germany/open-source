import subprocess
import tempfile
import unittest
from pathlib import Path
from credential_hygiene import audit_snapshot, inspect_blob


class CredentialHygieneTests(unittest.TestCase):
    def test_environment_files_are_blocked(self):
        for name in (".env", "config/.env.production", "nested/.ENV.local"):
            with self.subTest(name=name):
                self.assertIn("environment credentials file", inspect_blob(name, b""))

    def test_environment_templates_and_public_keys_are_allowed(self):
        for name in (".env.example", ".env.sample", ".env.template", "id_rsa.pub"):
            with self.subTest(name=name):
                self.assertEqual([], inspect_blob(name, b"PLACEHOLDER"))

    def test_credential_containers_and_state_are_blocked(self):
        for name in ("id_ed25519", "cert.pfx", "cert.p12", "terraform.tfstate",
                     "terraform.tfstate.backup", ".aws/credentials"):
            with self.subTest(name=name):
                self.assertTrue(inspect_blob(name, b""))

    def test_private_keys_detected_in_arbitrary_files(self):
        for kind in ("", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "):
            marker = ("-----BEGIN " + kind + "PRIVATE KEY" + "-----").encode()
            self.assertIn("private-key material", inspect_blob("notes.txt", marker))

    def test_ordinary_documentation_is_allowed(self):
        self.assertEqual([], inspect_blob("README.md", b"Never commit private keys."))

    def test_git_snapshot_ignores_untracked_files_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.run(["git", "-C", temp, *args], check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            git("init")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            (root / ".env").write_text("EXAMPLE=not-a-real-secret\n")
            (root / "README.md").write_text("Example\n")
            (root / "outside-link").symlink_to("/file-that-does-not-exist")
            git("add", ".")
            git("commit", "-m", "Fixture")
            (root / ".env.local").write_text("untracked\n")
            self.assertEqual([(".env", "environment credentials file")],
                             audit_snapshot(cwd=temp))


if __name__ == "__main__":
    unittest.main()
