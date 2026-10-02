"""File Hash Checker

Computes cryptographic hashes for a file or every file in a folder and
flags any that match a list of known hashes (for example, indicators of
compromise from a threat report).

Examples:
    python hashcheck.py samples
    python hashcheck.py samples --algo sha1 --known known.txt
    python hashcheck.py samples --known known.txt --csv results.csv
"""

import argparse
import csv
import hashlib
import sys
from pathlib import Path

CHUNK_SIZE = 8192  # read files 8 KB at a time so large files don't fill memory


def hash_file(path, algo="sha256"):
    """Return the hex digest of a file, reading it in small chunks."""
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_files(path):
    """Return a list of files: the file itself, or every file under a folder."""
    p = Path(path)
    if p.is_file():
        return [p]
    return sorted(f for f in p.rglob("*") if f.is_file())


def load_known(path):
    """Load known hashes from a text file.

    One hash per line. Only the first word on each line is used, and lines
    starting with # are treated as comments. Hashes are lowercased so the
    comparison is case-insensitive.
    """
    with open(path, encoding="utf-8") as f:
        return {
            line.split()[0].lower()
            for line in f
            if line.strip() and not line.lstrip().startswith("#")
        }


def write_csv(rows, out_path):
    """Save results to a CSV file."""
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["hash", "algorithm", "path", "match"])
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="File hash checker")
    parser.add_argument("path", help="file or folder to hash")
    parser.add_argument("--algo", default="sha256", choices=["md5", "sha1", "sha256"],
                        help="hash algorithm (default: sha256)")
    parser.add_argument("--known", help="text file with one known hash per line")
    parser.add_argument("--csv", help="save results to this CSV file")
    args = parser.parse_args()

    # Check inputs up front and give clear messages instead of a traceback.
    if not Path(args.path).exists():
        sys.exit(f"Error: path not found: {args.path}")

    known = set()
    if args.known:
        try:
            known = load_known(args.known)
        except (OSError, UnicodeDecodeError) as e:
            sys.exit(f"Error: cannot read known-hash file '{args.known}': {e}")

    rows = []
    skipped = 0
    for f in collect_files(args.path):
        try:
            digest = hash_file(f, args.algo)
        except OSError as e:
            print(f"[skip] {f}: {e}")
            skipped += 1
            continue
        matched = digest in known
        flag = "  <-- MATCH" if matched else ""
        print(f"{digest}  {f}{flag}")
        rows.append([digest, args.algo, str(f), "yes" if matched else "no"])

    if args.csv:
        try:
            write_csv(rows, args.csv)
        except OSError as e:
            sys.exit(f"Error: cannot write CSV '{args.csv}': {e}")

    # Summary goes to stderr so it doesn't pollute output redirected to a file.
    matches = sum(1 for r in rows if r[3] == "yes")
    print(f"\nScanned {len(rows)} file(s), {matches} match(es), {skipped} skipped.",
          file=sys.stderr)


if __name__ == "__main__":
    main()