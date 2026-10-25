#!/usr/bin/env python3
"""Extract haugene/vpn-configs-contrib provider trees into dest/<provider>/.

Scripts are skipped. The custom provider is skipped. A symlink is written as a
regular file when its target is a kept file in the archive. Link text with a
trailing newline is trimmed so the fastestvpn and purevpn defaults still resolve.
"""

import os
import posixpath
import sys
import tarfile

KEEP_EXT = {
    ".ovpn",
    ".conf",
    ".openvpn",
    ".crt",
    ".key",
    ".pem",
    ".p12",
    ".cer",
    ".txt",
    ".cr",
}
MAX_UNCOMPRESSED = 96 << 20
MAX_FILE = 8 << 20
MAX_MEMBERS = 20000


def safe_elem(part):
    return part not in ("", ".", "..") and not any(c in part for c in "/\\\n\r")


def split_contrib(name):
    parts = name.split("/")
    for i, part in enumerate(parts):
        if part != "openvpn" or i + 1 >= len(parts):
            continue
        provider = parts[i + 1]
        rel_parts = parts[i + 2 :]
        if not rel_parts or not safe_elem(provider) or provider == "custom":
            return None
        if any(not safe_elem(p) for p in rel_parts):
            return None
        return provider, "/".join(rel_parts)
    return None


def keep_rel(rel):
    base = posixpath.basename(rel)
    if base == "updateConfigs.sh" or base.lower() == "desktop.ini":
        return False
    ext = posixpath.splitext(base)[1].lower()
    if ext in KEEP_EXT:
        return True
    return ext == ""


def clean_link(text):
    text = text.replace("\n", "").replace("\r", "").strip()
    if text.startswith("./"):
        text = text[2:]
    if not text or text.startswith("/") or "\\" in text:
        return None
    parts = text.split("/")
    if any(not safe_elem(p) for p in parts):
        return None
    return "/".join(parts)


def main():
    if len(sys.argv) != 3:
        print("usage: extract-contrib.py <tarball> <dest>", file=sys.stderr)
        return 2
    src, dest = sys.argv[1], sys.argv[2]
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(src, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            print("tarball has too many members", file=sys.stderr)
            return 1
        regular = {}
        links = []
        total = 0
        for m in members:
            name = posixpath.normpath(m.name)
            if name.startswith("/") or ".." in m.name.split("/") or "\n" in m.name or "\r" in m.name:
                print(f"unsafe path {m.name!r}", file=sys.stderr)
                return 1
            parsed = split_contrib(name)
            if parsed is None:
                continue
            provider, rel = parsed
            if not keep_rel(rel):
                continue
            if m.isfile():
                if m.size > MAX_FILE:
                    print(f"file too large {name}", file=sys.stderr)
                    return 1
                body = tf.extractfile(m).read()
                total += len(body)
                if total > MAX_UNCOMPRESSED:
                    print("tarball expands too far", file=sys.stderr)
                    return 1
                regular[name] = (provider, rel, body)
            elif m.issym():
                target = clean_link(m.linkname or "")
                if target is None:
                    continue
                links.append((name, provider, rel, target))
        for name, provider, rel, target in links:
            parent = posixpath.dirname(name)
            target_name = posixpath.normpath(posixpath.join(parent, target))
            got = regular.get(target_name)
            if got is None:
                continue
            total += len(got[2])
            if total > MAX_UNCOMPRESSED:
                print("tarball expands too far", file=sys.stderr)
                return 1
            regular[name] = (provider, rel, got[2])
    providers = set()
    files = 0
    for provider, rel, body in regular.values():
        out = os.path.join(dest, provider, *rel.split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(body)
        os.chmod(out, 0o644)
        providers.add(provider)
        files += 1
    if not providers:
        print("no providers extracted", file=sys.stderr)
        return 1
    print(f"providers={len(providers)} files={files}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
