"""Deterministic SPDX 2.2 enrichment of a fresh Windows publish; no legal clearance.

The generated document is retained byte for byte. Verification recomputes the
only allowed transformation using hash-bound nuspec witnesses and current
physical coverage. Archives are read only during enrichment, never executed.
"""
import argparse
import base64
import copy
import hashlib
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote, unquote, urlsplit
import xml.etree.ElementTree as ET
import zipfile

import release_licenses as legal
from release_bundle import coverage

DIRECTORY = '_manifest/enrichment'
ORIGINAL = DIRECTORY + '/generated.spdx.json'
SIDECAR = ORIGINAL + '.sha256'
PROVENANCE = DIRECTORY + '/provenance.json'
FORMAT = 'querypact-spdx-enrichment-1'
# Keep package-content and declaration-scope uncertainties explicit in generated evidence.
SCOPE_REASONS = {
    'bouncycastle.cryptography': 'Associated ASF NOTICE applicability and zlib altered-source/marking scope remain unresolved.',
    'modelcontextprotocol': 'MIT-to-Apache transition, contribution consent, and documentation licensing scope remain unresolved.',
    'modelcontextprotocol.core': 'MIT-to-Apache transition, contribution consent, and documentation licensing scope remain unresolved.',
    'microsoft.netcore.app.runtime.win-x64': 'Runtime contains third-party material; publisher MIT does not describe the complete runtime contents.',
    'pgsqlparser': 'Managed MIT declaration does not describe the native libpg_query/PostgreSQL contents; native compilation attribution remains open.',
    'yamldotnet': 'Publisher MIT does not describe all retained libyaml/ObjectPool licensing in the contents.',
    'testcontainers': 'Copied Apache-licensed regex source and generated helper output have unresolved licensing scope.',
    'testcontainers.postgresql': 'Generated helper output licensing scope remains unresolved.',
}
DOCKER_REASON = 'Generated model/build output licensing scope remains unresolved; no MIT-only output assertion.'
DECLARATIONS = {'MIT', 'Apache-2.0', 'BSD-3-Clause', 'PostgreSQL'}


def identity(name, version):
    legal.require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', name)
                  and isinstance(version, str) and re.fullmatch(r'[A-Za-z0-9.+-]+', version),
                  'Invalid exact package identity')
    return name.casefold(), version.casefold()


def encoded(document):
    return (legal.json.dumps(document, indent=2, ensure_ascii=True) + '\n').encode('utf-8')


def read(path):
    def pairs(rows):
        result = {}
        for key, value in rows:
            legal.require(key not in result, 'Duplicate JSON property')
            result[key] = value
        return result
    return legal.json.loads(legal.nonempty(path).decode('utf-8-sig'), object_pairs_hook=pairs)


def validate_document(output, document, files):
    """Validate the supported generator profile plus every checksum/reference.

    Independent SPDX validation is a review check, not a product dependency.
    Unknown conclusions require a separate future evidence workflow.
    """
    legal.require(document.get('spdxVersion') == 'SPDX-2.2'
                  and document.get('dataLicense') == 'CC0-1.0'
                  and document.get('SPDXID') == 'SPDXRef-DOCUMENT'
                  and document.get('name') and urlsplit(document.get('documentNamespace', '')).scheme in ('http', 'https'),
                  'Invalid SPDX 2.2 document header')
    info = document.get('creationInfo', {})
    legal.require('Tool: Microsoft.SBOMTool-4.1.5' in info.get('creators', [])
                  and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', info.get('created', '')),
                  'Unsupported generator provenance')
    legal.require(not document.get('externalDocumentRefs') and not document.get('snippets')
                  and not document.get('hasExtractedLicensingInfos'), 'Unsupported SPDX profile')
    ids, keys, purls = {document['SPDXID']}, set(), set()
    legal.require(isinstance(document.get('packages'), list) and document['packages'], 'No SPDX packages')
    for row in document['packages'] + document.get('files', []):
        sid = row.get('SPDXID', '')
        legal.require(re.fullmatch(r'SPDXRef-[A-Za-z0-9.-]+', sid) and sid not in ids, 'Invalid/duplicate SPDX ID')
        ids.add(sid)
        legal.require(row.get('licenseConcluded') == 'NOASSERTION' and row.get('copyrightText'),
                      'Unsupported conclusion or missing copyright field')
    for row in document['packages']:
        key = identity(row['name'], row.get('versionInfo'))
        legal.require(key not in keys, 'Case-insensitive package identity collision')
        keys.add(key)
        legal.require(row.get('downloadLocation') and isinstance(row.get('filesAnalyzed'), bool)
                      and row.get('licenseDeclared') in DECLARATIONS | {'NOASSERTION'}, 'Invalid package fields')
        if row['filesAnalyzed']:
            code = row.get('packageVerificationCode', {}).get('packageVerificationCodeValue', '')
            legal.require(re.fullmatch(r'[a-f0-9]{40}', code) and row.get('licenseInfoFromFiles'),
                          'Missing package verification fields')
        else:
            legal.require('packageVerificationCode' not in row, 'Unexpected package verification code')
        for ref in row.get('externalRefs', []):
            if ref.get('referenceType') != 'purl':
                continue
            locator = ref.get('referenceLocator', '')
            legal.require(locator.startswith('pkg:') and ref.get('referenceCategory') == 'PACKAGE-MANAGER', 'Invalid PURL')
            canonical = unquote(locator).casefold()
            legal.require(canonical not in purls, 'Duplicate PURL')
            purls.add(canonical)
            if locator.startswith('pkg:nuget/'):
                legal.require(canonical == f'pkg:nuget/{key[0]}@{key[1]}', 'PURL identity/version contradiction')
    for target in document.get('documentDescribes', []):
        legal.require(target in ids, 'Unknown documentDescribes target')
    legal.require(document.get('documentDescribes'), 'Missing documentDescribes')
    for row in document['packages']:
        legal.require(all(x in ids for x in row.get('hasFiles', [])), 'Unknown hasFiles target')
    for rel in document.get('relationships', []):
        legal.require(rel.get('spdxElementId') in ids and rel.get('relatedSpdxElement') in ids | {'NONE', 'NOASSERTION'}
                      and rel.get('relationshipType'), 'Invalid SPDX relationship')
    legal.validate_spdx_files(output, document, files)
    for row in document['files']:
        path = legal.safe_path(output, row['fileName'].removeprefix('./'))
        algorithms = set()
        for check in row['checksums']:
            algo = check['algorithm']
            legal.require(algo in ('SHA1', 'SHA256') and algo not in algorithms, 'Unsupported/duplicate file checksum')
            algorithms.add(algo)
            legal.require(hashlib.new(algo.lower(), path.read_bytes()).hexdigest() == check['checksumValue'].lower(),
                          'Original file checksum mismatch')
    for row in document['packages']:
        if row['filesAnalyzed']:
            owned = [f for f in document['files'] if f['SPDXID'] in row.get('hasFiles', [])]
            excluded = row['packageVerificationCode'].get('packageVerificationCodeExcludedFiles', [])
            values = [next(c['checksumValue'] for c in f['checksums'] if c['algorithm'] == 'SHA1')
                      for f in owned if f['fileName'] not in excluded]
            # 4.1.5 uses uppercase SHA1 strings; also accept the usual lower
            # case calculation. Preserve the original bytes in either case.
            codes = {hashlib.sha1(''.join(sorted(f(v) for v in values)).encode()).hexdigest()
                     for f in (str.lower, str.upper)}
            legal.require(row['packageVerificationCode']['packageVerificationCodeValue'] in codes,
                          'Package verification code mismatch')


def context(output, original):
    expected = {legal.SPDX, legal.SPDX + '.sha256'}
    if (output / DIRECTORY).exists():
        expected |= {ORIGINAL, SIDECAR, PROVENANCE}
    present = {p.relative_to(output).as_posix() for p in (output / '_manifest').rglob('*') if p.is_file()}
    legal.require_file_inventory(present, expected, 'Stale/unexpected manifest files')
    files = legal.validate_notices(output)
    evidence = read(output / legal.EVIDENCE)
    physical = coverage(output / 'querypact.exe', evidence)
    legal.require(physical == evidence.get('physicalBundle') and not physical['hashMismatches']
                  and not physical['entriesWithoutInput'], 'Incomplete physical coverage')
    # The outer apphost input is not a bundle entry; no other missing input is allowed.
    legal.require(physical['inputsWithoutEntry'] in ([], ['querypact.exe']), 'Missing effective bundle payload')
    validate_document(output, original, files)
    sources = {}
    for row in evidence['packages'] + evidence['effectiveRuntimePacks']:
        key = identity(row['id'], row['version'])
        legal.require(key not in sources, 'Case-insensitive metadata collision')
        legal.require(row['source'].rstrip('/').lower() == 'https://api.nuget.org/v3/index.json', 'Untrusted NuGet source')
        sources[key] = row
    effective = {identity(r['package'], r['version']) for r in evidence['bundleInputs'] if 'package' in r}
    verified = {identity(r['package'], r['version']) for r in physical['verifiedInputs'] if 'package' in r}
    legal.require(effective == verified and verified <= sources.keys(), 'Missing effective package metadata/coverage')
    existing = {identity(r['name'], r['versionInfo']) for r in original['packages']}
    for key in verified - existing:
        legal.require(not any(k[0] == key[0] for k in existing), 'Existing SPDX version contradicts effective version')
    return evidence, physical, {key: sources[key] for key in sorted(verified)}


def validate_nuspec(raw, meta):
    legal.require(len(raw) <= 1024 * 1024 and legal.sha(raw) == meta['nuspecSha256'], 'Nuspec hash contradiction')
    legal.require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Unsafe nuspec XML')
    doc = ET.fromstring(raw)
    def field(name):
        nodes = [e for e in doc.iter() if e.tag.split('}')[-1] == name]
        legal.require(len(nodes) <= 1, 'Duplicate nuspec metadata')
        return nodes[0] if nodes else None
    name, version, license_node, repo = [field(n) for n in ('id', 'version', 'license', 'repository')]
    legal.require(name is not None and version is not None and name.text == meta['id'] and version.text == meta['version'],
                  'Exact nuspec identity/version contradiction')
    declared = None if license_node is None else {'type': license_node.get('type'), 'value': license_node.text}
    legal.require(declared == meta['license'] and (None if repo is None else dict(repo.attrib)) == meta['repository'],
                  'Nuspec declaration/repository contradiction')


def archive_witness(meta, owned, roots):
    key = identity(meta['id'], meta['version'])
    relative = f'{key[0]}/{key[1]}/{key[0]}.{key[1]}.nupkg'
    candidates = {legal.safe_path(root, relative) for root in roots if legal.safe_path(root, relative).is_file()}
    legal.require(candidates, f'Exact source archive unavailable: {key[0]}/{key[1]}')
    for archive in sorted(candidates):
        legal.require(archive.stat().st_size <= 512 * 1024 * 1024, 'Oversized source archive')
        data = archive.read_bytes()
        legal.require(legal.sha(data) == meta['nupkgSha256'] and
                      base64.b64encode(hashlib.sha512(data).digest()).decode() == meta['nupkgSha512'],
                      'Source archive hash contradiction')
    with zipfile.ZipFile(sorted(candidates)[0]) as z:
        legal.archive_has_primary_text(z)
        legal.require(sum(r.file_size for r in z.infolist()) <= 1024 * 1024 * 1024, 'Oversized archive contents')
        names = [n for n in z.namelist() if '/' not in n and n.lower().endswith('.nuspec')]
        legal.require(len(names) == 1 and z.getinfo(names[0]).file_size <= 1024 * 1024, 'Ambiguous/oversized nuspec')
        raw = z.read(names[0])
        validate_nuspec(raw, meta)
        for row in owned:
            legal.safe_path(Path('/unused-archive-root'), row['packagePath'])
            legal.require(z.getinfo(row['packagePath']).file_size == row['bytes']
                          and legal.sha(z.read(row['packagePath'])) == row['sha256'], 'Archive payload contradiction')
    return {'id': meta['id'], 'version': meta['version'], 'nupkgSha256': meta['nupkgSha256'],
            'nuspecBase64': base64.b64encode(raw).decode(),
            'verifiedArchivePayloads': [{'packagePath': r['packagePath'], 'sha256': r['sha256'], 'bytes': r['bytes']}
                                        for r in owned]}


def transformation(original, sources, physical, witnesses):
    legal.require(len(witnesses) == len(sources), 'Missing/extra provenance witnesses')
    proofs = {}
    for witness in witnesses:
        key = identity(witness['id'], witness['version'])
        legal.require(key in sources and key not in proofs, 'Duplicate/unmatched provenance witness')
        meta = sources[key]
        validate_nuspec(base64.b64decode(witness['nuspecBase64'], validate=True), meta)
        owned = [r for r in physical['verifiedInputs'] if 'package' in r and identity(r['package'], r['version']) == key]
        expected = {'id': meta['id'], 'version': meta['version'], 'nupkgSha256': meta['nupkgSha256'],
                    'nuspecBase64': witness['nuspecBase64'],
                    'verifiedArchivePayloads': [{'packagePath': r['packagePath'], 'sha256': r['sha256'], 'bytes': r['bytes']}
                                                for r in owned]}
        legal.require(witness == expected, 'Malformed archive witness')
        proofs[key] = witness
    result = copy.deepcopy(original)
    existing = {identity(r['name'], r['versionInfo']): r for r in result['packages']}
    operations, matrix = [], []
    for key, meta in sources.items():
        if key in existing:
            continue
        sid = 'SPDXRef-Enriched-NuGet-' + legal.sha(encoded(list(key)))
        row = {'name': meta['id'], 'versionInfo': meta['version'], 'SPDXID': sid,
               'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseDeclared': 'NOASSERTION',
               'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION', 'supplier': 'NOASSERTION',
               'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl',
                                 'referenceLocator': f'pkg:nuget/{quote(meta["id"], safe=".-_")}@{quote(meta["version"], safe=".-_")}'}],
               'comment': 'Physical package identity verified by publish inputs, bundle byte hashes and exact NuGet archive. No relationship asserted: these observations do not establish generator graph or SPDX containment semantics.'}
        result['packages'].append(row)
        operations.append({'operation': 'add-package', 'SPDXID': sid, 'package': copy.deepcopy(row)})
        existing[key] = row
    originals = {r['SPDXID']: r for r in original['packages']}
    for row in result['packages']:
        key = identity(row['name'], row['versionInfo'])
        before = originals.get(row['SPDXID'])
        legal.require(before is None or before.get('licenseDeclared') == 'NOASSERTION', 'Original declaration lacks supported assertion provenance')
        meta = sources.get(key)
        reason = SCOPE_REASONS.get(key[0])
        if key[0].startswith('docker.dotnet.enhanced'):
            reason = DOCKER_REASON
        if meta is None:
            reason = 'Exact physical identity attribution unresolved.' if key[0] == 'querypact' else 'No physically verified effective input; declaration scope not established for this candidate.'
        declaration = meta.get('license') if meta else None
        if not reason and (not declaration or declaration['type'] != 'expression' or declaration['value'] not in DECLARATIONS):
            reason = 'Unsupported or absent exact publisher expression; no contents declaration inferred.'
        if not reason:
            reason = 'Exact NuGet publisher expression only; no comprehensive licensing or conclusion for all contents asserted.'
            fields = {'licenseDeclared': declaration['value'],
                      'licenseComments': reason + ' Exact nuspec SHA256: ' + meta['nuspecSha256'] + '.'}
            # Only these two existing fields may change, and only via this decision.
            for field, value in fields.items():
                operations.append({'operation': 'set-field', 'SPDXID': row['SPDXID'], 'field': field,
                                   'before': row.get(field), 'after': value})
                row[field] = value
        matrix.append({'name': row['name'], 'version': row['versionInfo'], 'SPDXID': row['SPDXID'],
                       'added': before is None, 'licenseDeclaredBefore': before.get('licenseDeclared') if before else None,
                       'licenseDeclaredAfter': row['licenseDeclared'], 'licenseConcluded': row['licenseConcluded'],
                       'declarationReason': reason, 'conclusionReason': 'No separately supported license conclusion; physical hashes and metadata do not establish one.',
                       'relationshipReason': 'Original generator relationships preserved.' if before else row['comment']})
    return result, operations, matrix


def provenance(output, original_hash, sidecar_hash, enriched, operations, matrix, witnesses):
    return {'schema': 1, 'format': FORMAT, 'publicReleaseGate': 'BLOCKED', 'spdxModified': True,
            'enrichmentScriptSha256': legal.digest(Path(__file__)),
            'originalSpdxPath': ORIGINAL, 'originalSpdxSha256': original_hash,
            'originalSidecarSha256': sidecar_hash, 'enrichedSpdxPath': legal.SPDX,
            'enrichedSpdxSha256': legal.sha(encoded(enriched)), 'exeSha256': legal.digest(output / 'querypact.exe'),
            'publishEvidenceSha256': legal.digest(output / legal.EVIDENCE),
            'inventorySha256': legal.digest(output / legal.INVENTORY),
            'operations': operations, 'packages': matrix, 'archiveWitnesses': witnesses,
            'limitation': 'Archive checks were performed at enrichment using the recorded NuGet restore trust boundary. Offline verification rechecks hash-bound nuspecs and physical payload witnesses, not archive availability, signatures, vendor builds or legal clearance.'}


def verify(output):
    report = read(output / PROVENANCE)
    present = {p.relative_to(output).as_posix() for p in (output / DIRECTORY).rglob('*') if p.is_file()}
    legal.require_file_inventory(present, {ORIGINAL, SIDECAR, PROVENANCE}, 'Unexpected enrichment files')
    original = read(output / ORIGINAL)
    legal.require(legal.nonempty(output / SIDECAR).decode('utf-8-sig').strip().lower() == legal.digest(output / ORIGINAL),
                  'Invalid original sidecar')
    evidence, physical, sources = context(output, original)
    enriched, operations, matrix = transformation(original, sources, physical, report['archiveWitnesses'])
    validate_document(output, enriched, legal.validate_notices(output))
    expected = provenance(output, legal.digest(output / ORIGINAL), legal.digest(output / SIDECAR),
                          enriched, operations, matrix, report['archiveWitnesses'])
    legal.require(report == expected, 'Malformed/stale enrichment provenance')
    legal.require(legal.nonempty(output / legal.SPDX) == encoded(enriched), 'Unauthorized SPDX transformation')
    legal.require(legal.nonempty(output / (legal.SPDX + '.sha256')) == (report['enrichedSpdxSha256'] + '\n').encode(),
                  'Invalid enriched sidecar')
    return report


def state(output):
    paths = [output / p for p in (ORIGINAL, SIDECAR, PROVENANCE)]
    if (output / DIRECTORY).exists() or any(p.exists() for p in paths):
        legal.require(all(p.is_file() for p in paths), 'Partial enrichment provenance')
        return verify(output)
    document = read(output / legal.SPDX)
    legal.require(all(r.get('licenseDeclared', 'NOASSERTION') == 'NOASSERTION'
                      and r.get('licenseConcluded', 'NOASSERTION') == 'NOASSERTION'
                      for r in document['packages']), 'License assertions require enrichment provenance')
    legal.require(not any(r.get('SPDXID', '').startswith('SPDXRef-Enriched-') or 'licenseComments' in r
                          for r in document['packages']), 'Enrichment provenance missing')
    return None


def enrich(output, roots):
    legal.require(not (output / 'SHA256SUMS.txt').exists() and not (output / legal.REPORT).exists(), 'Stale checksums/reconciliation refused')
    legal.require(not (output / DIRECTORY).exists(), 'Enrichment rerun/partial output refused')
    original = read(output / legal.SPDX)
    sidecar = output / (legal.SPDX + '.sha256')
    legal.require(sidecar.is_file(), 'Original generator sidecar required')
    legal.validate_manifest_sidecar(output)
    evidence, physical, sources = context(output, original)
    witnesses = [archive_witness(meta, [r for r in physical['verifiedInputs'] if 'package' in r
                                      and identity(r['package'], r['version']) == key], roots)
                 for key, meta in sources.items()]
    enriched, operations, matrix = transformation(original, sources, physical, witnesses)
    validate_document(output, enriched, legal.validate_notices(output))
    report = provenance(output, legal.digest(output / legal.SPDX), legal.digest(sidecar), enriched, operations, matrix, witnesses)
    # All refusals above occur before writes. A partial I/O failure leaves a
    # marker directory which every subsequent consumer refuses until verified.
    target = output / DIRECTORY
    target.mkdir(parents=True)
    (output / ORIGINAL).write_bytes((output / legal.SPDX).read_bytes())
    (output / SIDECAR).write_bytes(sidecar.read_bytes())
    legal.write(output / PROVENANCE, report)
    (output / legal.SPDX).write_bytes(encoded(enriched))
    sidecar.write_bytes((report['enrichedSpdxSha256'] + '\n').encode('ascii'))
    return verify(output)


def default_roots():
    roots = [Path(os.environ.get('NUGET_PACKAGES', str(Path.home() / '.nuget/packages')))]
    for root in (os.environ.get('DOTNET_ROOT'), str(Path(os.environ.get('ProgramFiles', '/unused')) / 'dotnet')):
        if root:
            roots.append(Path(root) / 'packs')
    return roots


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('enrich', 'verify'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--package-root', action='append', type=Path)
    args = parser.parse_args()
    try:
        report = enrich(args.output, args.package_root or default_roots()) if args.command == 'enrich' else verify(args.output)
        print(legal.json.dumps({'spdxModified': report['spdxModified'], 'packages': len(report['packages']), 'publicReleaseGate': 'BLOCKED'}))
    except (ValueError, OSError, KeyError, TypeError, ET.ParseError, zipfile.BadZipFile) as error:
        parser.exit(1, f'SPDX enrichment error: {error}\n')


if __name__ == '__main__':
    main()
