"""Offline release evidence, notices, reconciliation and checksum checks.

MSBuild evidence is a record of bundle inputs, not proof of full SBOM coverage.
Reviewed notices require exact archive identity and independent payload hashes.
SPDX enrichment is verified separately; reconciliation never clears the public gate.
"""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import shutil
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT_NOTICES = ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md")
INVENTORY = "redistribution/inventory.json"
EVIDENCE = "redistribution/publish-evidence.json"
REPORT = "license-reconciliation.json"
SPDX = "_manifest/spdx_2.2/manifest.spdx.json"
PACKAGE_NOTICES = "redistribution/package-notices.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def require_file_inventory(present, expected, message):
    # Relative paths only; JSON escapes control characters for safe CI logs.
    # Do not read unexpected files or print their contents or absolute paths.
    unexpected, missing = sorted(present - expected), sorted(expected - present)
    require(not unexpected and not missing,
            f"{message}; unexpected paths: {json.dumps(unexpected, ensure_ascii=True)}; "
            f"missing paths: {json.dumps(missing, ensure_ascii=True)}")


def nonempty(path):
    require(path.is_file() and path.stat().st_size > 0,
            f"Required file absent or empty: {path}")
    data = path.read_bytes()
    require(data.strip(), f"Required text/content is blank: {path}")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return sha(nonempty(path))


def archive_has_primary_text(archive):
    """Validate ZIP paths and detect primary license files at any depth."""
    primary_names = {"license", "license.txt", "license.md", "copying", "copying.txt"}
    seen = {}
    has_primary_text = False
    for entry in archive.infolist():
        name = entry.filename
        is_directory = entry.is_dir()
        path = name[:-1] if is_directory and name.endswith("/") else name
        parts = path.split("/")
        require(path and not path.startswith("/") and "\\" not in path and ":" not in path
                and not any(ord(c) < 32 for c in path)
                and all(part and part not in (".", "..") for part in parts),
                f"Unsafe or ambiguous ZIP path: {json.dumps(name, ensure_ascii=True)}")
        folded = "/".join(part.casefold() for part in parts)
        ancestors = ["/".join(folded.split("/")[:index]) for index in range(1, len(parts))]
        require(not any(seen.get(parent) is False for parent in ancestors),
                f"Ambiguous ZIP path: {json.dumps(name, ensure_ascii=True)}")
        require(folded not in seen,
                f"Duplicate or ambiguous ZIP path: {json.dumps(name, ensure_ascii=True)}")
        require(is_directory or not any(existing.startswith(folded + "/") for existing in seen),
                f"Ambiguous ZIP path: {json.dumps(name, ensure_ascii=True)}")
        seen[folded] = is_directory
        if not is_directory and parts[-1].casefold() in primary_names:
            has_primary_text = True
    return has_primary_text


def load(path):
    return json.loads(nonempty(path).decode("utf-8-sig"))


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def safe_path(root, relative):
    require(isinstance(relative, str) and relative and "\\" not in relative
            and ":" not in relative and not any(ord(c) < 32 for c in relative)
            and not PurePosixPath(relative).is_absolute()
            and all(p and p not in (".", "..") for p in relative.split("/")),
            f"Invalid inventory path: {json.dumps(relative, ensure_ascii=True)}")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()) and path != root.resolve(),
            f"Path escapes publish directory: {relative}")
    return path


def prepare(output):
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())),
            f"Publish output must be empty (old/partial output refused): {output}")
    output.mkdir(parents=True, exist_ok=True)


def read_rows(path, fields):
    rows = []
    # An excluded-input file can legitimately be empty.
    require(path.is_file(), f"Missing current publish evidence: {path}")
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.strip():
            row = line.split("|")
            require(len(row) == fields, f"Malformed MSBuild evidence: {path}")
            rows.append(row)
    return rows


def package(directory, expected_id, expected_version, official=False, expected_content_hash=None):
    """Validate restored identity, archive hash and exact nuspec, offline.

    NuGet restore metadata is the source trust boundary; this is not an online
    signature or certificate revocation check.
    """
    stem = f"{expected_id.lower()}.{expected_version.lower()}"
    archive = directory / (stem + ".nupkg")
    data = nonempty(archive)
    metadata = load(directory / ".nupkg.metadata")
    content_hash = base64.b64encode(hashlib.sha512(data).digest()).decode()
    # NuGet metadata hashes unsigned content for signed packages; the sidecar
    # hashes the entire archive. They are deliberately different hash domains.
    require(metadata.get("contentHash"), f"Missing NuGet restore content hash: {archive}")
    if expected_content_hash is not None:
        require(expected_content_hash == metadata["contentHash"], f"Restore content hash mismatch: {archive}")
    require(content_hash == nonempty(directory / (stem + ".nupkg.sha512")).decode().strip(),
            f"Invalid nupkg hash (NuGet SHA512 sidecar): {archive}")
    source = metadata.get("source", "")
    if official:
        require(source.rstrip("/").lower() == "https://api.nuget.org/v3/index.json",
                f"Runtime pack must come from official NuGet restore: {source}")
    with zipfile.ZipFile(archive) as z:
        nuspecs = [n for n in z.namelist() if n.lower().endswith(".nuspec") and "/" not in n]
        require(len(nuspecs) == 1, f"Ambiguous nuspec: {archive}")
        raw = z.read(nuspecs[0])
    doc = ET.fromstring(raw)
    def element(name):
        matches = [e for e in doc.iter() if e.tag.split("}")[-1] == name]
        require(len(matches) <= 1, f"Contradictory/duplicate nuspec {name}: {archive}")
        return matches[0] if matches else None
    id_node, ver_node, license_node = element("id"), element("version"), element("license")
    repository_node = element("repository")
    require(id_node is not None and ver_node is not None and id_node.text and ver_node.text and
            id_node.text.lower() == expected_id.lower() and
            ver_node.text.lower() == expected_version.lower(),
            f"Source package version/identity differs from resolved pack: {expected_id}/{expected_version}")
    return {"id": id_node.text, "version": ver_node.text, "source": source,
            "nupkgSha256": sha(data), "nupkgSha512": content_hash,
            "restoreContentHash": metadata["contentHash"], "nuspecSha256": sha(raw),
            "repository": None if repository_node is None else dict(repository_node.attrib),
            "license": None if license_node is None else
            {"type": license_node.get("type"), "value": license_node.text}}, archive


def notice_path(reviewed):
    return f"redistribution/packages/{reviewed['id']}/{reviewed['version']}/{reviewed['archiveEntry']}"


def reviewed_texts(policy):
    """Expand additional texts without allowing them to change package identity.

    Each original keeps its own bytes/source, even when several packages use
    the same document. The parent binds every text to its exact NuGet identity.
    """
    identities = [(p["id"].lower(), p["version"].lower()) for p in policy]
    require(len(identities) == len(set(identities)), "Duplicate reviewed package identity")
    result = []
    allowed = {"archiveEntry", "sha256", "sourceType", "upstream", "referencedText", "linkedText",
               "obligation", "applicability"}
    for parent in policy:
        primary = {k: v for k, v in parent.items() if k != "additionalNotices"}
        result.append(primary)
        for additional in parent.get("additionalNotices", []):
            require(set(additional) <= allowed, "Additional notice identity/attribution contradiction")
            require(all(additional.get(k) for k in ("archiveEntry", "sha256", "sourceType",
                                                    "obligation", "applicability")),
                    "Incomplete additional notice selection")
            row = {k: v for k, v in primary.items() if k not in ("upstream", "sourceType")}
            row.update(additional, noticeRole="additional")
            result.append(row)
    paths = [notice_path(r).casefold() for r in result]
    require(len(paths) == len(set(paths)), "Duplicate reviewed notice path")
    return result


def notice_source(reviewed, meta):
    """Bind upstream texts to the repository revision in the exact nuspec.

    A shared SPDX expression is never a provenance link. Reviewed policy is
    the offline trust anchor; staging does not fetch moving branches or tags.
    """
    kind = reviewed.get("sourceType", "archive")
    require(kind in ("archive", "upstream", "referenced", "linked"), "Unsupported reviewed notice source")
    if kind == "archive":
        return reviewed["url"]
    upstream = reviewed["upstream"]
    repository = upstream["repository"]
    require(repository == meta.get("repository") and repository.get("type") == "git",
            "Upstream repository/revision contradicts exact nuspec")
    require(re.fullmatch(r"[0-9a-f]{40}", repository.get("commit", "")) is not None,
            "Upstream revision must be an immutable Git commit")
    url = repository.get("url", "").removesuffix(".git")
    require(re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", url) is not None,
            "Unsupported upstream repository URL")
    safe_path(Path.cwd(), upstream["path"])
    expected = (f"https://raw.githubusercontent.com/{url.removeprefix('https://github.com/')}"
                f"/{repository['commit']}/{upstream['path']}")
    require(upstream["url"] == expected, "Upstream text URL/revision mismatch")
    if kind == "linked":
        require(reviewed.get("noticeRole") == "additional", "Linked primary text refused")
        target = reviewed.get("linkedText")
        require(isinstance(target, dict)
                and all(target.get(k) for k in ("repository", "path", "url", "cachedPath", "reference"))
                and isinstance(target["repository"], dict)
                and isinstance(target["reference"], dict)
                and all(target["reference"].get(k) for k in ("path", "cachedPath", "sha256")),
                "Incomplete linked notice evidence")
        target_repo = target["repository"]
        require(target_repo.get("type") == "git"
                and re.fullmatch(r"[0-9a-f]{40}", target_repo.get("commit", "")) is not None,
                "Linked revision must be an immutable Git commit")
        target_url = target_repo.get("url", "").removesuffix(".git")
        require(re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", target_url) is not None,
                "Unsupported linked repository URL")
        safe_path(Path.cwd(), target["path"])
        safe_path(Path.cwd(), target["cachedPath"])
        safe_path(Path.cwd(), target["reference"]["path"])
        safe_path(Path.cwd(), target["reference"]["cachedPath"])
        raw = (f"https://raw.githubusercontent.com/{target_url.removeprefix('https://github.com/')}"
               f"/{target_repo['commit']}/{target['path']}")
        require(target["url"] == raw, "Linked text URL/revision mismatch")
        for evidence in (upstream, target["reference"]):
            require(re.fullmatch(r"[0-9a-f]{64}", evidence.get("sha256", "")) is not None,
                    "Missing linked reference source hash")
        return raw
    if kind == "referenced":
        require(reviewed.get("noticeRole") == "additional", "Referenced primary text refused")
        # A license expressly referenced by an exact-revision source file is
        # a different provenance chain from a license selected by analogy.
        reference = reviewed["referencedText"]
        require(reference["url"] == "https://www.apache.org/licenses/LICENSE-2.0.txt",
                "Unsupported referenced license URL")
        require(re.fullmatch(r"[0-9a-f]{64}", upstream.get("sha256", "")) is not None,
                "Missing reference source hash")
        return reference["url"]
    return expected


def stage(repo, output, evidence_dir):
    require(not (output / INVENTORY).exists(), "Old notices/inventory refused")
    exe_hash = digest(output / "querypact.exe")
    native = load(repo / "redistribution/native-sources.json")
    notices = []
    for entry in native["notices"]:
        source = safe_path(repo, entry["path"])
        require(digest(source) == entry["sha256"], f"Invalid upstream notice hash: {source}")
        target = safe_path(output, entry["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        notices.append(entry)
    for relative in ROOT_NOTICES + ("redistribution/native-sources.json", "redistribution/README.md", PACKAGE_NOTICES):
        target = safe_path(output, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        nonempty(repo / relative)
        shutil.copyfile(repo / relative, target)

    assets = load(evidence_dir / "project.assets.json")
    require("net10.0/win-x64" in assets["targets"], "Restore has no win-x64 target")
    folders = [Path(p) for p in assets["packageFolders"]]
    packages = []
    package_dirs = {}
    for key, info in assets["libraries"].items():
        if info["type"] != "package":
            continue
        name, version = key.rsplit("/", 1)
        matches = [f / info["path"] for f in folders if (f / info["path"]).is_dir()]
        require(len(matches) == 1, f"Missing/ambiguous exact restored package: {key}")
        meta, _ = package(matches[0], name, version, expected_content_hash=info.get("sha512"))
        packages.append(meta)
        package_dirs[(name.lower(), version.lower())] = matches[0].resolve()

    excluded = {Path(p).resolve() for p, _ in read_rows(evidence_dir / "excluded.tsv", 2)}
    inputs = [(Path(p).resolve(), relative) for p, relative in read_rows(evidence_dir / "bundle.tsv", 2)
              if Path(p).resolve() not in excluded]
    require(inputs, "No effective bundle inputs captured")
    packs, unused_packs = [], []
    for name, version, directory in read_rows(evidence_dir / "packs.tsv", 3):
        directory = Path(directory).resolve()
        effective = [(p, r) for p, r in inputs if p.is_relative_to(directory)]
        if not effective:
            unused_packs.append({"id": name, "version": version,
                                 "evidence": "ResolvedRuntimePack, no effective bundle input"})
            continue
        require(name.lower().endswith(".runtime.win-x64") and
                name.lower().startswith("microsoft."), f"Unexpected effective runtime pack: {name}")
        meta, archive = package(directory, name, version, official=True)
        packs.append(meta)
        package_dirs[(name.lower(), version.lower())] = directory
        with zipfile.ZipFile(archive) as z:
            for filename in ("LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"):
                data = z.read(filename)
                require(data.strip(), f"Empty runtime notice: {name}/{version}/{filename}")
                require(nonempty(directory / filename) == data,
                        f"Cached runtime notice differs from exact source package: {filename}")
                relative = f"redistribution/dotnet/{name}/{version}/{filename}"
                target = safe_path(output, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                notices.append({"path": relative, "component": name, "version": version,
                                "source": meta["source"], "sha256": sha(data),
                                "nupkgSha256": meta["nupkgSha256"], "archiveEntry": filename})
    require(any(p["id"].lower() == "microsoft.netcore.app.runtime.win-x64" for p in packs),
            "No effective Microsoft.NETCore.App.Runtime.win-x64 pack evidenced")

    input_report = []
    for path, relative in inputs:
        owners = [(name, version) for (name, version), directory in package_dirs.items()
                  if path.is_relative_to(directory)]
        require(len(owners) <= 1, f"Ambiguous input owner: {relative}")
        row = {"bundlePath": relative, "sha256": digest(path)}
        if owners:
            row["package"], row["version"] = owners[0]
            row["packagePath"] = path.relative_to(package_dirs[owners[0]]).as_posix()
        input_report.append(row)
    binary = native["nativeBinary"]
    native_inputs = [r for r in input_report if r.get("package") == binary["package"] and
                     r.get("version") == binary["version"] and r.get("packagePath") == binary["asset"]]
    require(len(native_inputs) == 1 and native_inputs[0]["sha256"] == binary["sha256"],
            "Native DLL identity/version not demonstrated in current bundle inputs")
    native_path = package_dirs[(binary["package"], binary["version"])] / binary["asset"]
    require(native_path.stat().st_size == binary["bytes"], "Native DLL size differs")
    # Only reviewed exact-version texts for independently verified payloads.
    from release_bundle import coverage
    physical = coverage(output / "querypact.exe", {"exeSha256": exe_hash, "bundleInputs": input_report})
    require(not physical["hashMismatches"],
            "Bundle payload hashes differ from current inputs; staging refused (possible intervening build)")
    selected = []
    policy = reviewed_texts(load(repo / PACKAGE_NOTICES)["packages"])
    for reviewed in policy:
        safe_path(repo, reviewed["archiveEntry"])
        key = (reviewed["id"].lower(), reviewed["version"].lower())
        owned = [r for r in input_report if (r.get("package"), r.get("version")) == key]
        if not owned:
            continue
        require(all(any(v["bundlePath"].replace("\\", "/") == r["bundlePath"].replace("\\", "/")
                        for v in physical["verifiedInputs"]) for r in owned),
                f"Reviewed package payload not physically verified: {key}")
        meta = next(p for p in packages if (p["id"].lower(), p["version"].lower()) == key)
        require(meta["license"] == {"type": "expression", "value": reviewed["licenseExpression"]}
                and meta["nupkgSha256"] == reviewed["nupkgSha256"]
                and meta["nuspecSha256"] == reviewed["nuspecSha256"],
                f"Reviewed package license/source contradiction: {key}")
        directory = package_dirs[key]
        source = notice_source(reviewed, meta)
        archive = directory / f"{key[0]}.{key[1]}.nupkg"
        with zipfile.ZipFile(archive) as z:
            if reviewed.get("sourceType", "archive") in ("upstream", "referenced", "linked"):
                require(reviewed.get("noticeRole") == "additional" or not archive_has_primary_text(z),
                        "Primary text present in exact archive; upstream fallback refused")
                data = nonempty(safe_path(repo, reviewed["upstream"]["cachedPath"]))
                if reviewed["sourceType"] == "linked":
                    target = reviewed["linkedText"]
                    reference = target["reference"]
                    target_repo = target["repository"]
                    link = (f"{target_repo['url'].removesuffix('.git')}/blob/"
                            f"{target_repo['commit']}/{reference['path']}")
                    require(sha(data) == reviewed["upstream"]["sha256"]
                            and link.encode("utf-8") in data,
                            "Linked notice anchor changed or lacks exact source link")
                    original = nonempty(safe_path(repo, reference["cachedPath"]))
                    require(sha(original) == reference["sha256"], "Linked original source changed")
                    data = nonempty(safe_path(repo, target["cachedPath"]))
                if reviewed["sourceType"] == "referenced":
                    require(sha(data) == reviewed["upstream"]["sha256"]
                            and b"http://www.apache.org/licenses/LICENSE-2.0" in data,
                            "Referenced license source changed or lacks license link")
                    data = nonempty(safe_path(repo, reviewed["referencedText"]["cachedPath"]))
            else:
                data = z.read(reviewed["archiveEntry"])
            for row in owned:
                safe_path(directory, row["packagePath"])
                require(sha(z.read(row["packagePath"])) == row["sha256"],
                        f"Reviewed payload differs from exact source archive: {key}")
        require(data.strip() and sha(data) == reviewed["sha256"], "Reviewed archive notice hash mismatch")
        relative = notice_path(reviewed)
        target = safe_path(output, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        selected.append(reviewed)
        notices.append({"path": relative, "component": reviewed["id"], "version": reviewed["version"],
                        "source": source, "sha256": reviewed["sha256"],
                        "nupkgSha256": reviewed["nupkgSha256"], "archiveEntry": reviewed["archiveEntry"]})
    write(output / INVENTORY, {"schema": 2, "notices": notices, "effectiveRuntimePacks": packs,
                               "reviewedPackageNotices": selected,
                               "nativeBinary": binary})
    write(output / EVIDENCE, {"schema": 1, "exeSha256": exe_hash,
                              "assetsSha256": digest(evidence_dir / "project.assets.json"),
                              "packages": packages, "effectiveRuntimePacks": packs,
                              "resolvedPacksWithoutBundleInputs": unused_packs,
                              "bundleInputs": input_report,
                              "physicalBundle": physical,
                              "publishComplete": False,
                              "limitation": "Physical payload hashes audited; apphost and full license obligations pending."
                              if physical else "MSBuild inputs; bundle contents not independently inspected."})
    validate_notices(output, require_complete=False)


def validate_notices(output, require_complete=True):
    inventory = load(output / INVENTORY)
    evidence = load(output / EVIDENCE)
    require(not require_complete or evidence.get("publishComplete") is True,
            "Publish incomplete (failure after publish or smoke); no checksums allowed")
    require(digest(output / "querypact.exe") == evidence["exeSha256"], "Executable changed after publish")
    if evidence.get("physicalBundle") is not None:
        from release_bundle import coverage
        require(coverage(output / "querypact.exe", evidence) == evidence["physicalBundle"],
                "Physical bundle evidence changed")
    native = load(output / "redistribution/native-sources.json")
    expected_native = {r["path"]: r["sha256"] for r in native["notices"]}
    actual = {r["path"]: r["sha256"] for r in inventory["notices"]}
    require(len(actual) == len(inventory["notices"]), "Duplicate notice paths")
    require(all(actual.get(p) == h for p, h in expected_native.items()), "Missing/invalid native inventory")
    for entry in native["notices"]:
        require(next(n for n in inventory["notices"] if n["path"] == entry["path"]) == entry,
                "Native notice attribution mismatch")
    packs = inventory["effectiveRuntimePacks"]
    require(packs == evidence["effectiveRuntimePacks"] and packs, "Runtime inventory/evidence mismatch")
    expected_runtime = set()
    for pack in packs:
        for filename in ("LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"):
            relative = f"redistribution/dotnet/{pack['id']}/{pack['version']}/{filename}"
            expected_runtime.add(relative)
            require(relative in actual, f"Missing runtime notice inventory: {relative}")
            notice = next(n for n in inventory["notices"] if n["path"] == relative)
            require(notice == {"path": relative, "component": pack["id"], "version": pack["version"],
                               "source": pack["source"], "sha256": actual[relative],
                               "nupkgSha256": pack["nupkgSha256"], "archiveEntry": filename},
                    "Runtime notice attribution mismatch")
    expected_packages = set()
    if inventory.get("schema") == 2:
        policy = reviewed_texts(load(output / PACKAGE_NOTICES)["packages"])
        effective = {(r["package"], r["version"]) for r in evidence["bundleInputs"] if "package" in r}
        selected = [r for r in policy if (r["id"].lower(), r["version"].lower()) in effective]
        require(inventory["reviewedPackageNotices"] == selected, "Reviewed notice selection incomplete")
        sources = {(r["id"].lower(), r["version"].lower()): r for r in evidence["packages"]}
        for reviewed in inventory["reviewedPackageNotices"]:
            require(reviewed in policy, "Unreviewed package notice")
            key = (reviewed["id"].lower(), reviewed["version"].lower())
            meta = sources.get(key)
            require(meta and meta["license"] == {"type": "expression", "value": reviewed["licenseExpression"]}
                    and meta["nupkgSha256"] == reviewed["nupkgSha256"]
                    and meta["nuspecSha256"] == reviewed["nuspecSha256"], "Reviewed notice source mismatch")
            relative = notice_path(reviewed)
            require(actual.get(relative) == reviewed["sha256"], "Reviewed notice inventory hash mismatch")
            notice = next(n for n in inventory["notices"] if n["path"] == relative)
            require(notice == {"path": relative, "component": reviewed["id"],
                               "version": reviewed["version"], "source": notice_source(reviewed, meta),
                               "sha256": reviewed["sha256"], "nupkgSha256": reviewed["nupkgSha256"],
                               "archiveEntry": reviewed["archiveEntry"]},
                    "Reviewed notice attribution mismatch")
            require(relative not in expected_packages, "Duplicate reviewed package notice")
            expected_packages.add(relative)
    require(set(actual) == set(expected_native) | expected_runtime | expected_packages, "Obsolete/unexpected notice entry")
    for relative, expected_hash in actual.items():
        require(digest(safe_path(output, relative)) == expected_hash,
                f"Invalid redistribution notice hash: {relative}")
    for relative in ROOT_NOTICES + (INVENTORY, EVIDENCE, "redistribution/README.md"):
        nonempty(output / relative)
    expected_files = set(actual) | {INVENTORY, EVIDENCE, "redistribution/README.md",
                                    "redistribution/native-sources.json"}
    if inventory.get("schema") == 2:
        expected_files.add(PACKAGE_NOTICES)
    present = {p.relative_to(output).as_posix() for p in (output / "redistribution").rglob("*") if p.is_file()}
    require_file_inventory(present, expected_files, "Obsolete/unexpected redistribution files")
    return expected_files | set(ROOT_NOTICES) | {"querypact.exe"}


def reconciliation(output):
    # Even incomplete candidates can have an auditable BLOCKED report; they
    # cannot receive checksums or pass artifact verification.
    legal_files = validate_notices(output, require_complete=False)
    spdx = load(output / SPDX)
    validate_manifest_sidecar(output)
    validate_spdx_files(output, spdx, legal_files)
    require(spdx.get("spdxVersion") == "SPDX-2.2", "Unexpected SPDX format; reconciliation blocked")
    require(isinstance(spdx.get("packages"), list) and spdx["packages"], "SPDX has no packages")
    from release_sbom import state
    enrichment = state(output)
    evidence = load(output / EVIDENCE)
    sources = {(p["id"].lower(), p["version"].lower()): p for p in
               evidence["packages"] + evidence["effectiveRuntimePacks"]}
    effective = {(p["package"], p["version"]) for p in evidence["bundleInputs"] if "package" in p}
    unused = {(p["id"].lower(), p["version"].lower()) for p in evidence.get("resolvedPacksWithoutBundleInputs", [])}
    rows, seen, ids = [], set(), set()
    for p in spdx["packages"]:
        require(p.get("SPDXID") and p["SPDXID"] not in ids, "Missing/duplicate SPDX package identifier")
        ids.add(p["SPDXID"])
        key = (p["name"].lower(), p.get("versionInfo", "").lower())
        require(key not in seen, "Duplicate SPDX package identity")
        seen.add(key)
        meta = sources.get(key)
        own = key[0] == "querypact"
        declared = p.get("licenseDeclared")
        exact = meta.get("license") if meta else None
        comparison = "NOASSERTION-unresolved" if declared == "NOASSERTION" else (
            "exact-expression-match" if (own and declared == "MIT") or
            (exact and exact["type"] == "expression" and exact["value"] == declared)
            else "unverified-or-mismatch")
        rows.append({"SPDXID": p["SPDXID"], "name": p["name"], "version": p.get("versionInfo"),
                     "licenseDeclared": p.get("licenseDeclared"),
                     "licenseComparison": comparison,
                     "exactNuGetMetadata": meta,
                     "savLicenseEvidence": {"expression": "MIT", "path": "LICENSE",
                                            "sha256": digest(output / "LICENSE")} if own else None,
                     "effectiveBundleInput": key in effective,
                     "noticePaths": [n["path"] for n in load(output / INVENTORY)["notices"]
                                     if (n["component"].lower() == key[0] and
                                         n.get("version", key[1]).lower() == key[1]) or
                                     (key == ("pgsqlparser", "1.0.0") and n["path"].startswith("redistribution/pgsqlparser/"))],
                     "status": "own-source-evidence" if own else
                     "exact-package-metadata" if meta else
                     "resolved-pack-without-bundle-input" if key in unused else "unmatched-unverified"})
    report = {"schema": 1, "publicReleaseGate": "BLOCKED", "spdxModified": enrichment is not None,
              "spdxSha256": digest(output / SPDX), "exeSha256": evidence["exeSha256"],
              "publishComplete": evidence.get("publishComplete", False),
              "resolvedPacksWithoutBundleInputs": evidence.get("resolvedPacksWithoutBundleInputs", []),
              "noAssertionCount": sum(p.get("licenseDeclared") == "NOASSERTION" for p in spdx["packages"]),
              "packages": rows,
              "nugetOnly": [v for k, v in sorted(sources.items()) if k not in seen],
              "effectiveInputsMissingFromSpdx": [list(k) for k in sorted(effective - seen)],
              "blockers": ["Declarations are bounded publisher metadata; conclusions and complete licensing remain unresolved." if enrichment else
                           "SPDX is unchanged; NOASSERTION is not resolved by this report.",
                           "Build/runtime environment packages cannot be claimed as physically distributed without evidence.",
                           "Full physical bundle coverage and all redistributed notice obligations need review.",
                           "Final Windows plus Linux PostgreSQL smoke and public disclosure gates remain external."]}
    if not report["publishComplete"]:
        report["blockers"].append("Publish smokes not completed; checksum generation and artifact verification prohibited.")
    if evidence.get("physicalBundle") is not None:
        from release_bundle import classify
        report["publishEvidenceSha256"] = digest(output / EVIDENCE)
        report["inventorySha256"] = digest(output / INVENTORY)
        report["coverageAudit"] = classify(spdx, evidence, evidence["physicalBundle"], enrichment)
    if enrichment:
        report["originalSpdxSha256"] = enrichment["originalSpdxSha256"]
        report["enrichmentProvenanceSha256"] = digest(output / "_manifest/enrichment/provenance.json")
        report["enrichmentOperations"] = enrichment["operations"]
        report["declarationMatrix"] = enrichment["packages"]
    return report


def reconcile(output):
    require(not (output / REPORT).exists() and not (output / "SHA256SUMS.txt").exists(),
            "Stale reconciliation/checksums refused")
    report = reconciliation(output)
    write(output / REPORT, report)
    return report


def validate_manifest_sidecar(output):
    sidecar = output / (SPDX + ".sha256")
    if sidecar.exists():
        require(nonempty(sidecar).decode("utf-8-sig").strip().lower() == digest(output / SPDX),
                "Invalid SPDX manifest SHA256 sidecar")


def validate_spdx_files(output, spdx, required_files):
    """Bind the SPDX loose-file checksums to this candidate, not its internals."""
    found = set()
    for entry in spdx.get("files", []):
        relative = entry["fileName"]
        if relative.startswith("./"):
            relative = relative[2:]
        require(relative not in found, f"Duplicate SPDX file: {relative}")
        values = [c["checksumValue"].lower() for c in entry.get("checksums", [])
                  if c["algorithm"] == "SHA256"]
        require(values == [digest(safe_path(output, relative))],
                f"SPDX file SHA256 does not match current candidate: {relative}")
        found.add(relative)
    require(required_files <= found, "SPDX loose-file coverage is missing executable/legal evidence")


def checksum_files(output):
    files = validate_notices(output)
    require((output / SPDX).is_file() and (output / REPORT).is_file(),
            "SPDX and reconciliation required before checksums")
    validate_manifest_sidecar(output)
    validate_spdx_files(output, load(output / SPDX), files)
    report = load(output / REPORT)
    require(report == reconciliation(output), "Stale reconciliation report or incorrect physical reconciliation")
    require(report["spdxSha256"] == digest(output / SPDX) and
            report["exeSha256"] == digest(output / "querypact.exe"), "Stale reconciliation report")
    files |= {SPDX, REPORT}
    # Include the generator's own manifest sidecar and other manifest evidence.
    files |= {p.relative_to(output).as_posix() for p in (output / "_manifest").rglob("*") if p.is_file()}
    present = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}
    require_file_inventory(present - {"SHA256SUMS.txt"}, files, "Unexpected files in publish output")
    return files


def checksums(output):
    require(not (output / "SHA256SUMS.txt").exists(), "Old checksums refused")
    files = checksum_files(output)
    lines = [f"{digest(safe_path(output, p))}  {p}\n" for p in sorted(files)]
    (output / "SHA256SUMS.txt").write_text("".join(lines), encoding="utf-8")
    verify(output)


def verify(output, public=False):
    expected = checksum_files(output)
    found = {}
    for line in nonempty(output / "SHA256SUMS.txt").decode("utf-8-sig").splitlines():
        value, relative = line.split("  ", 1)
        require(relative not in found, "Duplicate checksum entry")
        require(value == digest(safe_path(output, relative)), f"Invalid checksum: {relative}")
        found[relative] = value
    require(set(found) == expected, "Checksum coverage differs from publish inventory")
    report = load(output / REPORT)
    require(report.get("publicReleaseGate") == "BLOCKED", "Unsupported reconciliation gate state")
    if public:
        raise ValueError("Public release BLOCKED; review license-reconciliation.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "stage", "complete", "validate", "reconcile", "checksums", "verify"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--public-release", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare(args.output)
        elif args.action == "stage":
            require(args.evidence is not None, "Current MSBuild evidence directory required")
            stage(args.repo, args.output, args.evidence)
        elif args.action == "validate":
            validate_notices(args.output)
        elif args.action == "complete":
            validate_notices(args.output, require_complete=False)
            evidence = load(args.output / EVIDENCE)
            evidence["publishComplete"] = True
            write(args.output / EVIDENCE, evidence)
        elif args.action == "reconcile":
            report = reconcile(args.output)
            print(f"Public release BLOCKED; {report['noAssertionCount']} declarations remain NOASSERTION")
        elif args.action == "checksums":
            checksums(args.output)
        else:
            verify(args.output, args.public_release)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, ET.ParseError) as error:
        print(f"Release evidence error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
