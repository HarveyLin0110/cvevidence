"""Read declared package inventory as data, not deployed build identity."""
import re

NAME = r'[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,199}'
VERSION = r'[^\s\x00-\x1f\x7f]{1,100}'


def parse(lines):
    """Recognize list-installed output or installed control stanzas."""
    output = []
    nonempty = [(i, line) for i, line in enumerate(lines, 1) if line.strip()]
    pattern = re.compile(f'({NAME}) - ({VERSION})')
    if nonempty and all(pattern.fullmatch(line) for _, line in nonempty):
        for number, line in nonempty[:100]:
            match = pattern.fullmatch(line)
            output.append(dict(name=match[1], version=match[2], start_line=number,
                               end_line=number, inventory_format='OPKG_LIST_INSTALLED'))
        return output
    block = []
    for number, line in enumerate(list(lines) + [''], 1):
        if line.strip():
            block.append((number, line))
            continue
        if not block:
            continue
        fields = {}; invalid = False
        for _, value in block:
            if value.startswith((' ', '\t')):
                continue
            key, sep, text = value.partition(':')
            if not sep or key in fields:
                invalid = True
            fields[key] = text.strip()
        name = fields.get('Package', ''); version = fields.get('Version', '')
        status = fields.get('Status', '').split()
        if (not invalid and re.fullmatch(NAME, name) and re.fullmatch(VERSION, version)
                and len(status) == 3 and status[-1] == 'installed'):
            output.append(dict(name=name, version=version, start_line=block[0][0],
                               end_line=block[-1][0], inventory_format='INSTALLED_CONTROL_STANZA'))
        block = []
        if len(output) >= 100:
            break
    return output
