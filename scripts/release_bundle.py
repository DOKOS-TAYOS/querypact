"""Read-only .NET single-file v6.0 audit; never execute or extract payloads.

The report validates package and physical bundle attribution against current retained evidence.
Only uncompressed v6.0 bundles are supported; unknown formats fail closed.
"""
import struct
from collections import Counter
from pathlib import PurePosixPath

from release_licenses import require, sha

SIGNATURE = bytes.fromhex('8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae')
MAX_BYTES = 512 * 1024 * 1024


def relative_path(value):
    require(isinstance(value, str) and value and '\\' not in value and ':' not in value
            and not any(ord(c) < 32 for c in value), 'Invalid bundle path')
    parts = value.split('/')
    require(not PurePosixPath(value).is_absolute() and
            all(p and p not in ('.', '..') for p in parts), 'Invalid bundle path')
    return value


def inspect(path):
    require(path.is_file() and 0 < path.stat().st_size <= MAX_BYTES, 'Bundle size outside audit limit')
    data = path.read_bytes()
    require(data[:2] == b'MZ', 'Expected Windows PE bundle')
    require(len(data) >= 64, 'Truncated PE')
    pe = struct.unpack_from('<I', data, 60)[0]
    require(pe + 4 <= len(data) and data[pe:pe + 4] == b'PE\0\0', 'Invalid PE signature')
    marker = data.find(SIGNATURE)
    require(marker >= 8 and data.find(SIGNATURE, marker + 1) == -1, 'Missing/ambiguous bundle signature')
    header = struct.unpack_from('<q', data, marker - 8)[0]
    require(marker + len(SIGNATURE) <= header < len(data), 'Invalid bundle header offset')
    cursor = header

    def read(fmt):
        nonlocal cursor
        size = struct.calcsize(fmt)
        require(cursor + size <= len(data), 'Truncated bundle manifest')
        values = struct.unpack_from(fmt, data, cursor)
        cursor += size
        return values

    def string():
        nonlocal cursor
        size = 0
        for i in range(5):
            byte, = read('<B')
            size |= (byte & 127) << (7 * i)
            if not byte & 128:
                break
        else:
            raise ValueError('Invalid bundle string length')
        require(0 < size <= 4096 and cursor + size <= len(data), 'Invalid bundle string bounds')
        value = data[cursor:cursor + size].decode('utf-8', errors='strict')
        cursor += size
        return value

    major, minor, count = read('<IIi')
    require((major, minor) == (6, 0), 'Unsupported bundle version')
    require(0 < count <= 10000, 'Invalid bundle entry count')
    bundle_id = string()
    deps_offset, deps_size, config_offset, config_size, flags = read('<qqqqQ')
    require(flags == 0, 'Unsupported bundle flags')
    entries, names, ranges = [], set(), []
    for _ in range(count):
        offset, size, compressed, kind = read('<qqqB')
        name = relative_path(string())
        require(name.casefold() not in names, 'Duplicate bundle entry')
        names.add(name.casefold())
        require(compressed == 0, 'Compressed bundles unsupported by this audit')
        require(kind in range(6), 'Unknown bundle entry type')
        require(size > 0 and marker + len(SIGNATURE) <= offset and offset + size <= header,
                'Invalid bundle payload bounds')
        ranges.append((offset, offset + size))
        entries.append({'bundlePath': name, 'offset': offset, 'bytes': size,
                        'type': kind, 'sha256': sha(data[offset:offset + size])})
    ranges.sort()
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'Overlapping bundle payloads')
    for kind, location in ((3, (deps_offset, deps_size)), (4, (config_offset, config_size))):
        matching = [(r['offset'], r['bytes']) for r in entries if r['type'] == kind]
        require(matching == [location], 'Bundle config header/entry mismatch')
    return {'format': '6.0', 'exeSha256': sha(data), 'headerOffset': header,
            'manifestEnd': cursor, 'bundleId': bundle_id, 'entries': entries,
            'limitation': 'Payload bytes only; apphost, padding, PE resources and provenance of source-built assemblies remain separate.'}


def coverage(path, evidence):
    physical = inspect(path)
    require(physical['exeSha256'] == evidence['exeSha256'], 'Executable/evidence hash mismatch')
    inputs = {}
    for row in evidence['bundleInputs']:
        name = relative_path(row['bundlePath'].replace('\\', '/'))
        require(name.casefold() not in inputs, 'Duplicate effective bundle input')
        require(('package' in row) == ('version' in row), 'Incomplete input owner')
        inputs[name.casefold()] = row
    verified, mismatches, unknown = [], [], []
    present = set()
    for row in physical['entries']:
        name = row['bundlePath'].casefold()
        present.add(name)
        source = inputs.get(name)
        if source is None:
            unknown.append(row)
        elif row['sha256'] != source['sha256']:
            mismatches.append(row['bundlePath'])
        else:
            verified.append({**row, **{k: v for k, v in source.items() if k != 'sha256'}})
    missing = [r['bundlePath'] for n, r in inputs.items() if n not in present]
    return {**physical, 'verifiedInputs': verified, 'hashMismatches': mismatches,
            'entriesWithoutInput': unknown, 'inputsWithoutEntry': missing}


def classify(spdx, evidence, physical, enrichment=None):
    effective = {(r['package'].lower(), r['version'].lower()) for r in evidence['bundleInputs'] if 'package' in r}
    verified = {(r['package'].lower(), r['version'].lower()) for r in physical['verifiedInputs'] if 'package' in r}
    sources = {(r['id'].lower(), r['version'].lower()): r for r in evidence['packages'] + evidence['effectiveRuntimePacks']}
    unused = {(r['id'].lower(), r['version'].lower()) for r in evidence.get('resolvedPacksWithoutBundleInputs', [])}
    identities, ids = {}, set()
    for row in spdx['packages']:
        require(row.get('SPDXID') and row['SPDXID'] not in ids, 'Missing/duplicate SPDX identifier')
        ids.add(row['SPDXID'])
        key = (row['name'].lower(), row.get('versionInfo', '').lower())
        require(key not in identities, 'Duplicate SPDX package identity')
        identities[key] = {'name': row['name'], 'version': row.get('versionInfo'),
                           'SPDXID': row['SPDXID'], 'licenseDeclared': row.get('licenseDeclared')}
    for key in sorted(effective - identities.keys()):
        identities[key] = {'name': key[0], 'version': key[1], 'SPDXID': None, 'licenseDeclared': None}
    rows = []
    for key, row in identities.items():
        category = ('physically-verified' if key in verified else
                    'effective-input-not-physically-verified' if key in effective else
                    'resolved-without-effective-input' if key in sources or key in unused else 'unknown')
        # Absence in this input list alone cannot establish build-only status.
        meta = sources.get(key)
        rows.append({**row, 'presence': category, 'exactNuGetMetadata': meta,
                     'licenseStatus': 'pending-obligations-review',
                     'verifiedEntries': [r['bundlePath'] for r in physical['verifiedInputs']
                                         if (r.get('package', '').lower(), r.get('version', '').lower()) == key]})
    return {'publicReleaseGate': 'BLOCKED', 'spdxModified': enrichment is not None,
            'noAssertionCount': sum(r.get('licenseDeclared') == 'NOASSERTION' for r in rows),
            'missingSpdxCount': sum(r['SPDXID'] is None for r in rows),
            'presenceCounts': dict(Counter(r['presence'] for r in rows)), 'packages': rows,
            'physicalBundle': physical}


def main():
    import argparse
    import json
    from pathlib import Path
    import release_licenses as legal
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path,
                        help='New report outside the publish directory; original artifacts are read-only')
    args = parser.parse_args()
    try:
        require(not args.report.exists(), 'Old audit report refused')
        require(not args.report.resolve().is_relative_to(args.output.resolve()), 'Audit report must be outside publish directory')
        files = legal.validate_notices(args.output, require_complete=False)
        legal.validate_manifest_sidecar(args.output)
        spdx = legal.load(args.output / legal.SPDX)
        require(spdx.get('spdxVersion') == 'SPDX-2.2', 'Unsupported SPDX audit format')
        legal.validate_spdx_files(args.output, spdx, files)
        evidence = legal.load(args.output / legal.EVIDENCE)
        from release_sbom import state
        enrichment = state(args.output)
        report = classify(spdx, evidence, coverage(args.output / 'querypact.exe', evidence), enrichment)
        report['originalSpdxSha256'] = enrichment['originalSpdxSha256'] if enrichment else legal.digest(args.output / legal.SPDX)
        report['spdxSha256'] = legal.digest(args.output / legal.SPDX)
        if enrichment:
            report['enrichmentProvenanceSha256'] = legal.digest(args.output / '_manifest/enrichment/provenance.json')
        report['publishEvidenceSha256'] = legal.digest(args.output / legal.EVIDENCE)
        report['inventorySha256'] = legal.digest(args.output / legal.INVENTORY)
        report['auditScriptSha256'] = legal.digest(Path(__file__))
        report['sourceSpdxRelationshipsModified'] = False
        legal.write(args.report, report)
        print(json.dumps({k: report[k] for k in ('publicReleaseGate', 'noAssertionCount', 'missingSpdxCount', 'presenceCounts')}))
    except (ValueError, OSError, KeyError, UnicodeError, struct.error) as error:
        parser.exit(1, f'Bundle audit error: {error}\n')


if __name__ == '__main__':
    main()
