# Checksum / Fixity CLI

![Terminal checking file hashes against a manifest and flagging a discrepancy](assets/checksum-fixity-cli.png)

A local command-line tool for creating and checking file checksums.

It can:

- calculate checksums for selected files;
- create checksum manifests;
- verify files against a manifest; and
- turn expected/actual checksum CSV reports into full and exceptions-only registers.

The tool is read-only. It does not upload files, follow symbolic links, or silently overwrite outputs. SHA-256 is the default; MD5 and SHA-1 are available for legacy verification with a warning.

A checksum match confirms bit-level agreement with the expected value. It does not prove provenance or authenticity.

## Install

Requires Python 3.10 or later.

```bash
python3 -m pip install .
```

## Use

```bash
fixity hash record.pdf

fixity manifest /data/transfer \
  --recursive \
  --base-dir /data/transfer \
  --output /data/reports/transfer.sha256

fixity verify \
  --manifest /data/reports/transfer.sha256 \
  --base-dir /data/transfer \
  --format json

fixity review \
  --input verification-report.csv \
  --output-dir review/
```

Exit codes are `0` for a clean result, `1` for an internal failure, `2` for invalid input, `3` when an output already exists, and `4` when processing completes with discrepancies or skipped paths.

Run the tests with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
