# Archive safety fixtures

These are small synthetic archives for safe-unpack rejection tests. They contain
no malware, live payloads, credentials, or external target data.

Fixtures:

- `tar-traversal.tar`: tar entry with `../evil.txt`, expected `path_traversal`.
- `tar-symlink-escape.tar`: tar symlink escaping root, expected `unsafe_link`.
- `tar-hardlink-escape.tar`: tar hardlink escaping root, expected `unsafe_link`.
- `tar-oversize-marker.tar`: small file used with tiny test limits, expected
  `max_file_bytes_exceeded`.
- `zip-slip.zip`: zip entry with `../evil.py`, expected `path_traversal`.
- `wheel-zip-slip.whl`: wheel-shaped zip with traversal entry, expected
  `path_traversal` for the unsafe entry.

Regenerate and safety-check with:

```sh
python3 testdata/archives/generate_fixtures.py --verify
```
