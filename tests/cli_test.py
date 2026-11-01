"""Linux CLI integration tests; only Python's standard library is needed."""
import hashlib
import pathlib
import struct
import subprocess
import sys
import tempfile

exe = str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    db = root / 'db'
    db.mkdir()
    target = root / 'target'
    target.mkdir()
    sample = target / 'sample'
    record = db / 'signature'
    for size in [0, 1, 3, 54, 55, 56, 63, 64, 65, 119, 120, 127, 128, 65536, 65537]:
        data = bytes(i % 251 for i in range(size))
        sample.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        for binary in [False, True]:
            record.write_bytes(struct.pack('<8I', *struct.unpack('>8I', bytes.fromhex(digest)))
                               if binary else (digest + '\n').encode())
            result = subprocess.run([exe, str(target), str(db)], capture_output=True, text=True)
            assert result.returncode == 1, result
            assert digest in result.stdout and 'scanned=1 matches=1' in result.stdout, result.stdout
    (target / 'link').symlink_to(sample)
    result = subprocess.run([exe, str(target), str(db)], capture_output=True, text=True)
    assert 'scanned=1 matches=1' in result.stdout
    sample.write_bytes(b'unmatched')
    assert subprocess.run([exe, str(sample), str(db)], capture_output=True).returncode == 0
    record.write_text('invalid')
    assert subprocess.run([exe, str(target), str(db)], capture_output=True).returncode == 2
    assert subprocess.run([exe, str(root / 'missing'), str(db)], capture_output=True).returncode == 2
print('CLI integration tests passed')
