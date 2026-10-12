"""Bounded, read-only MFI metadata/span inspection; no signature/build claims.

Layout independently implemented from the supplied stage1/stage2 format notes.
Only the two observed vendor/model headers are recognized; no vendor tool runs.
"""
import hashlib
import struct

MAGICS = {(0xb3c00000, 0x10001): '2506', (0x964d0000, 0x10001): 'e5v40-01'}
MAX_IMAGE = 256 * 1024 * 1024
MAX_SPANS = 256


def inspect(path, *, enabled=True):
    size = path.stat().st_size
    result = {'parser': 'mfi-static-v1', 'status': 'UNSUPPORTED_FORMAT',
              'format': 'UNKNOWN', 'family': 'UNKNOWN', 'metadata': {}, 'spans': [],
              'rootfs': [], 'signature_verified': False, 'build_binding': 'UNKNOWN',
              'extraction_performed': False}
    with path.open('rb') as f:
        head = f.read(92)
        if len(head) < 20 or struct.unpack('<II', head[:8]) not in MAGICS:
            return result
        result.update(format='MFI', family=MAGICS[struct.unpack('<II', head[:8])])
        if not enabled:
            result['status'] = 'PARSER_UNAVAILABLE'
            return result
        try:
            _, _, version, header, end = struct.unpack('<IIIII', head[:20])
            if version != 2 or header != 92 or not header <= end <= size <= MAX_IMAGE:
                raise ValueError('header')
            count = 0

            def words(offset, n, limit):
                if offset < 0 or offset + 4*n > limit:
                    raise ValueError('bounds')
                f.seek(offset)
                return struct.unpack('<'+'I'*n, f.read(4*n))

            def span(offset, length, limit, kind):
                nonlocal count
                count += 1
                if count > MAX_SPANS or length < 0 or offset + length > limit:
                    raise ValueError('span limit')
                f.seek(offset); remaining = length; h = hashlib.sha256(); prefix = b''
                while remaining:
                    block = f.read(min(1024*1024, remaining))
                    if not block: raise ValueError('truncated')
                    if len(prefix) < 4096: prefix += block[:4096-len(prefix)]
                    h.update(block); remaining -= len(block)
                row = {'type': kind, 'offset': offset, 'length': length, 'sha256': h.hexdigest()}
                result['spans'].append(row)
                return row, prefix

            pos = header
            while pos < end:
                kind, total, length = words(pos, 3, end)
                if total < 12 or length > total-12 or pos+total > end: raise ValueError('stage1')
                row, prefix = span(pos+12, length, end, 'stage1:'+str(kind))
                if kind == 4 and length <= 4096:
                    text = prefix.decode('utf-8', errors='strict')
                    result['metadata'] = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
                    result['metadata'] = {k.strip(): v.strip() for k,v in result['metadata'].items()}
                    result['metadata_locator'] = row
                pos += total
            while pos < size:
                magic, kind, total, length, signature = words(pos, 5, size)
                if magic != 0xa7b263fe or total < 20 or length > total-20 or pos+total > size:
                    raise ValueError('stage2')
                if kind == 2:
                    sub = pos+20; stop = sub+length; fields = {}; locators = {}
                    while sub < stop:
                        sk, sl = words(sub, 2, stop)
                        if sl < 8 or sub+sl > stop: raise ValueError('rootfs')
                        row, prefix = span(sub+8, sl-8, stop, 'rootfs:'+str(sk))
                        if sk in (1,2,7) and sl-8 <= 4096:
                            fields[sk] = prefix.decode('utf-8', errors='strict').rstrip('\0')
                            locators[sk] = row
                        sub += sl
                    version_text = fields.get(2, '')
                    result['rootfs'].append({'name': fields.get(1,''), 'version': version_text,
                        'filename_declaration': fields.get(7,''), 'version_locator': locators.get(2),
                        'version_state': 'PRESENT_BUT_UNUSABLE' if not version_text or version_text.startswith('-')
                            else 'PRESENT'})
                pos += total
            result['status'] = 'PARTIAL_METADATA'
        except (ValueError, UnicodeError, struct.error):
            result.update(status='INVALID_CONTAINER', metadata={}, rootfs=[], spans=[])
    return result
