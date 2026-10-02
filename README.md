# File Hash Checker

A command-line tool written in Python that computes cryptographic hashes for a file or every file in a folder, and flags any file whose hash matches a list of known hashes, such as indicators of compromise (IOCs) from a threat report.

I built this as a practice project while studying malware analysis and endpoint security, to understand how hash-based detection works.

## Features

- Hashes a single file or an entire folder (including subfolders)
- Supports SHA-256 (default), SHA-1, and MD5
- Compares results against a user-supplied list of known hashes and flags matches
- Reads files in small chunks, so large files don't use much memory
- Skips unreadable files and reports them instead of crashing
- Clear error messages for a wrong path or missing known-hash file
- Optional CSV export of results
- Uses only the Python standard library, so there is nothing to install

## Requirements

- Python 3.8 or newer

## Usage

```
python hashcheck.py <path> [--algo {md5,sha1,sha256}] [--known KNOWN_FILE] [--csv OUTPUT_FILE]
```

| Option | Description |
|---|---|
| `path` | File or folder to hash |
| `--algo` | Hash algorithm: `md5`, `sha1`, or `sha256` (default: `sha256`) |
| `--known` | Text file containing known hashes, one per line |
| `--csv` | Save the results to a CSV file |

### Examples

Hash every file in a folder:

```
python hashcheck.py samples
```

Check a folder against a list of known hashes:

```
python hashcheck.py samples --known known.txt
```

Use SHA-1 and save the results to a CSV file:

```
python hashcheck.py samples --algo sha1 --known known.txt --csv results.csv
```

### Known-hash file format

A plain text file with one hash per line. Only the first word on each line is used, so you can add notes after the hash. Lines starting with `#` are ignored, and matching is case-insensitive.

```
# Example known.txt
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  test file a
```

The hashes in the file must use the same algorithm you run the tool with. A SHA-256 list will not match if you run with `--algo md5`.

## Sample Output

Running the tool on a folder with two files, where `a.txt` is on the known-hash list:

```
$ python hashcheck.py samples --known known.txt --csv results.csv
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  samples/a.txt  <-- MATCH
e258d248fda94c63753607f7c4494ee0fcbe92f1a76bfdac795c9d84101eb317  samples/b.txt

Scanned 2 file(s), 1 match(es), 0 skipped.
```

The contents of `results.csv`:

```
hash,algorithm,path,match
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03,sha256,samples/a.txt,yes
e258d248fda94c63753607f7c4494ee0fcbe92f1a76bfdac795c9d84101eb317,sha256,samples/b.txt,no
```

Error handling, for a mistyped path or a missing known-hash file:

```
$ python hashcheck.py wrongfolder
Error: path not found: wrongfolder

$ python hashcheck.py samples --known wrong.txt
Error: cannot read known-hash file 'wrong.txt': [Errno 2] No such file or directory: 'wrong.txt'
```

## How It Works

1. `collect_files` finds the files to check: the single file, or every file under a folder.
2. `hash_file` reads each file in 8 KB chunks and feeds them to Python's `hashlib`, then returns the hex digest.
3. `load_known` reads the known-hash list into a set, so each lookup is fast.
4. Each file's digest is looked up in that set. A hit is marked `MATCH`.

## Notes

- MD5 and SHA-1 are weak against deliberate tampering (collisions can be crafted), so SHA-256 is the default. They are included because they still appear in many threat reports and older tools.
- A matching hash means the file is byte-for-byte identical to a known sample. A non-matching hash does **not** mean a file is safe, since changing even one byte produces a completely different hash.
- Only scan files you own or have permission to examine.

## Possible Improvements

- Look up hashes against a threat-intelligence service
- Compare two folders to detect changed files
- Save a baseline of hashes and report any file that changes later

## License

MIT License. See the `LICENSE` file.

## Author

Kurt Sebastian Bautista
