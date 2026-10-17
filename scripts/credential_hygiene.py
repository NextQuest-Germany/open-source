"""Credential-file hygiene for the checked-out Git snapshot; not a full secret scanner."""
import json
import re
import subprocess
import sys
from pathlib import PurePosixPath

PRIVATE_KEY = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}


def inspect_blob(path, data):
    name = PurePosixPath(path).name.lower()
    parts = tuple(part.lower() for part in PurePosixPath(path).parts)
    findings = []
    if (name == ".env" or name.startswith(".env.")) and name not in ENV_TEMPLATES:
        findings.append("environment credentials file")
    if name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}:
        findings.append("SSH private-key filename")
    if name.endswith((".p12", ".pfx")):
        findings.append("credential container")
    if name.endswith(".tfstate") or ".tfstate." in name:
        findings.append("Terraform state")
    if len(parts) >= 2 and parts[-2:] == (".aws", "credentials"):
        findings.append("AWS credentials file")
    if PRIVATE_KEY.search(data):
        findings.append("private-key material")
    return findings


def audit_snapshot(cwd=None):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=cwd, stderr=subprocess.PIPE)

    failures = []
    entries = git("ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0")
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        if kind != b"blob":
            continue
        # Read Git blobs, not working-tree paths: never follow a symlink outside the repo.
        data = git("cat-file", "blob", object_id.decode("ascii"))
        path = raw_path.decode("utf-8", errors="surrogateescape")
        for reason in inspect_blob(path, data):
            failures.append((path, reason))
    return failures


def main():
    try:
        failures = audit_snapshot()
    except subprocess.CalledProcessError:
        print("Credential hygiene failed: Git snapshot could not be read.", file=sys.stderr)
        return 2
    for path, reason in failures:
        # Never print matched content. JSON escapes unusual filenames and newlines.
        print(json.dumps({"path": path, "reason": reason}, ensure_ascii=True))
    if failures:
        print("Remove sensitive files; rotate any exposed credentials. See SECURITY.md.")
        return 1
    print("Credential-file hygiene passed for HEAD (not a full secret/history scan).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
