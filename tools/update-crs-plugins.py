#!/usr/bin/env python3
"""Refresh pinned official CRS plugins; review new pins and profile versions separately."""
import argparse
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1] / "internal" / "crsplugins"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare pinned upstream bytes without writing")
    args = parser.parse_args()
    manifest = json.loads((ROOT / "manifest.json").read_text())
    checked = 0
    for plugin in manifest["plugins"]:
        if not plugin["shipped"]:
            continue
        repo, commit = plugin["repository"], plugin["commit"]
        if not re.fullmatch(r"https://github.com/coreruleset/[a-z0-9-]+-plugin", repo) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("Only pinned official coreruleset repositories are allowed")
        archive = urllib.request.urlopen("https://codeload.github.com/" + repo.removeprefix("https://github.com/") + "/tar.gz/" + commit, timeout=60).read()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            members = {str(PurePosixPath(*PurePosixPath(m.name).parts[1:])): m for m in tar.getmembers() if m.isfile()}
            for name in plugin["files"]:
                rel = PurePosixPath(name)
                if rel.is_absolute() or ".." in rel.parts:
                    raise ValueError("Invalid manifest path")
                source = tar.extractfile(members[name])
                if source is None:
                    raise ValueError("Missing upstream file: " + name)
                body = source.read()
                target = ROOT / "vendor" / plugin["name"] / name
                if args.check:
                    if not target.exists() or target.read_bytes() != body:
                        raise ValueError("Upstream bytes differ: " + str(target))
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(body)
                checked += 1
    print(f"{'Verified' if args.check else 'Refreshed'} {checked} pinned upstream files")

if __name__ == "__main__":
    main()
