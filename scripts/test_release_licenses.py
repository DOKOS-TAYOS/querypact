"""Synthetic offline tests; checksum script regressions require PowerShell."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

import release_licenses as legal

POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


class ReleaseLicenseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo, self.output, self.evidence = [self.root / n for n in ("repo", "drop", "evidence")]
        self.cache = self.root / "cache"
        self.evidence.mkdir()
        self.repo.mkdir()
        self.output.mkdir()

        real_repo = Path(__file__).resolve().parent.parent
        for n in legal.ROOT_NOTICES:
            shutil.copyfile(real_repo / n, self.repo / n)
        shutil.copytree(real_repo / "redistribution", self.repo / "redistribution")
        native = legal.load(self.repo / "redistribution/native-sources.json")
        self.dll = b"synthetic native input"
        native["nativeBinary"]["sha256"] = legal.sha(self.dll)
        native["nativeBinary"]["bytes"] = len(self.dll)
        legal.write(self.repo / "redistribution/native-sources.json", native)
        self.version = "10.0.99"  # Must work without pinning the CI #207 version.
        self.runtime_id = "Microsoft.NETCore.App.Runtime.win-x64"
        self.runtime = self.make_package(self.runtime_id, self.version,
                                         {"LICENSE.TXT": b"Microsoft original fixture\r\n",
                                          "THIRD-PARTY-NOTICES.TXT": b"Third party fixture\r\n",
                                          "runtimes/win-x64/native/coreclr.dll": b"runtime fixture"})
        self.parser = self.make_package("pgsqlparser", "1.0.0",
                                        {"runtimes/win-x64/native/libpg_query.dll": self.dll})
        assets = {"targets": {"net10.0/win-x64": {}}, "packageFolders": {str(self.cache): {}},
                  "libraries": {"pgsqlparser/1.0.0": {"type": "package", "path": "pgsqlparser/1.0.0"}}}
        legal.write(self.evidence / "project.assets.json", assets)
        (self.evidence / "packs.tsv").write_text(f"{self.runtime_id}|{self.version}|{self.runtime}\n")
        (self.evidence / "bundle.tsv").write_text(
            f"{self.runtime}/runtimes/win-x64/native/coreclr.dll|coreclr.dll\n"
            f"{self.parser}/runtimes/win-x64/native/libpg_query.dll|libpg_query.dll\n")
        (self.evidence / "excluded.tsv").write_text("")
        fixture = BundleAuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.make_bundle(payloads=[(2, "coreclr.dll", b"runtime fixture"),
                                      (2, "libpg_query.dll", self.dll),
                                      (3, "querypact.deps.json", b"{}"),
                                      (4, "querypact.runtimeconfig.json", b"{}")])
        shutil.copyfile(fixture.path, self.output / "querypact.exe")

    def make_package(self, name, version, files, nuspec_version=None, repository=None):
        directory = self.cache / name.lower() / version
        directory.mkdir(parents=True, exist_ok=True)
        stem = f"{name.lower()}.{version}"
        archive = directory / (stem + ".nupkg")
        repository_xml = (f'<repository type="git" url="{repository["url"]}" '
                          f'commit="{repository["commit"]}" />') if repository else ""
        nuspec = (f'<package><metadata><id>{name}</id><version>{nuspec_version or version}</version>'
                  f'<license type="expression">MIT</license>{repository_xml}</metadata></package>').encode()
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr(name + ".nuspec", nuspec)
            for relative, data in files.items():
                if relative.endswith("/") and data is None:
                    z.writestr(relative, b"")
                    continue
                z.writestr(relative, data)
                path = directory / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        content_hash = base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
        (directory / (stem + ".nupkg.sha512")).write_text(content_hash)
        legal.write(directory / ".nupkg.metadata",
                    {"contentHash": content_hash, "source": "https://api.nuget.org/v3/index.json"})
        return directory

    def stage(self, complete=True):
        legal.stage(self.repo, self.output, self.evidence)
        if complete:
            evidence = legal.load(self.output / legal.EVIDENCE)
            evidence["publishComplete"] = True
            legal.write(self.output / legal.EVIDENCE, evidence)

    def sbom(self):
        legal.write(self.output / legal.SPDX,
                    {"spdxVersion": "SPDX-2.2", "files": [
                        {"fileName": "./" + p, "checksums": [{"algorithm": "SHA256", "checksumValue": legal.digest(self.output / p)}]}
                        for p in sorted(legal.validate_notices(self.output, require_complete=False))], "packages": [
                        {"SPDXID": "SPDXRef-QueryPact", "name": "QueryPact", "versionInfo": "fixture",
                         "licenseDeclared": "NOASSERTION"},
                        {"SPDXID": "SPDXRef-unknown", "name": "unmatched", "versionInfo": "9",
                         "licenseDeclared": "NOASSERTION"}]})

    def packaged(self):
        self.stage()
        self.sbom()
        legal.reconcile(self.output)
        legal.checksums(self.output)

    def run_checksum_script(self):
        script = Path(__file__).resolve().parent / "New-Checksums.ps1"
        return subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(script),
             "-PublishDir", str(self.output)],
            capture_output=True, text=True, timeout=60)

    def snapshot_output(self):
        return {p.relative_to(self.output).as_posix(): p.read_bytes() if p.is_file() else None
                for p in self.output.rglob("*")}

    @unittest.skipUnless(POWERSHELL, "PowerShell required for script regression")
    def test_checksum_script_without_generate_sbom_requires_manifest_without_writes(self):
        # Missing output, an empty manifest directory, and a directory in place
        # of the required file must fail even before validating legal notices.
        for state in ("missing", "empty-directory", "manifest-is-directory"):
            with self.subTest(state=state):
                if state == "empty-directory":
                    (self.output / "_manifest").mkdir()
                elif state == "manifest-is-directory":
                    (self.output / legal.SPDX).mkdir(parents=True)
                before = self.snapshot_output()
                result = self.run_checksum_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Without -GenerateSbom", result.stdout + result.stderr)
                self.assertIn("Run with", result.stdout + result.stderr)
                self.assertIn("fresh publish directory", result.stdout + result.stderr)
                self.assertEqual(before, self.snapshot_output())

    @unittest.skipUnless(POWERSHELL, "PowerShell required for script regression")
    def test_checksum_script_reuses_valid_manifest_and_keeps_public_gate_blocked(self):
        self.stage()
        self.sbom()
        manifest = self.output / legal.SPDX
        (self.output / (legal.SPDX + ".sha256")).write_text(legal.digest(manifest))
        before = manifest.read_bytes()
        result = self.run_checksum_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, manifest.read_bytes())
        legal.verify(self.output)
        with self.assertRaisesRegex(ValueError, "Public release BLOCKED"):
            legal.verify(self.output, public=True)
        before = self.snapshot_output()
        result = self.run_checksum_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Old checksums refused", result.stdout + result.stderr)
        self.assertEqual(before, self.snapshot_output())

    @unittest.skipUnless(POWERSHELL, "PowerShell required for script regression")
    def test_checksum_script_refuses_invalid_existing_manifest_without_writes(self):
        self.stage()
        self.sbom()
        original = (self.output / legal.SPDX).read_bytes()
        sidecar = self.output / (legal.SPDX + ".sha256")
        for invalid in ("json", "sidecar", "hash", "coverage", "format", "packages"):
            with self.subTest(invalid=invalid):
                (self.output / legal.SPDX).write_bytes(original)
                if sidecar.exists():
                    sidecar.unlink()
                spdx = legal.load(self.output / legal.SPDX)
                if invalid == "json":
                    (self.output / legal.SPDX).write_text("{")
                elif invalid == "sidecar":
                    sidecar.write_text("0" * 64)
                else:
                    if invalid == "hash":
                        spdx["files"][0]["checksums"][0]["checksumValue"] = "0" * 64
                    elif invalid == "coverage":
                        spdx["files"] = []
                    elif invalid == "format":
                        spdx["spdxVersion"] = "SPDX-2.3"
                    else:
                        spdx["packages"] = []
                    legal.write(self.output / legal.SPDX, spdx)
                before = self.snapshot_output()
                result = self.run_checksum_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Without -GenerateSbom", result.stdout + result.stderr)
                self.assertEqual(before, self.snapshot_output())

    def test_new_runtime_version_and_original_bytes(self):
        self.stage()
        notice = self.output / f"redistribution/dotnet/{self.runtime_id}/{self.version}/LICENSE.TXT"
        self.assertEqual(notice.read_bytes(), b"Microsoft original fixture\r\n")
        self.assertEqual(legal.load(self.output / legal.INVENTORY)["effectiveRuntimePacks"][0]["version"], self.version)

    def test_resolved_pack_source_version_mismatch(self):
        self.make_package(self.runtime_id, self.version, {"LICENSE.TXT": b"x"}, nuspec_version="10.0.12")
        with self.assertRaisesRegex(ValueError, "version/identity"):
            self.stage()

    def test_missing_and_empty_original_notices(self):
        for content in (None, b"", b" \n"):
            with self.subTest(content=content):
                path = self.repo / "redistribution/pgsqlparser/LICENSE"
                if content is None:
                    path.unlink()
                else:
                    path.write_bytes(content)
                with self.assertRaises(ValueError):
                    self.stage()

    def test_invalid_native_notice_hash(self):
        (self.repo / "redistribution/pgsqlparser/LICENSE").write_text("changed legal text")
        with self.assertRaisesRegex(ValueError, "upstream notice hash"):
            self.stage()

    def test_invalid_package_hash(self):
        archive = next(self.runtime.glob("*.nupkg"))
        archive.write_bytes(archive.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValueError, "nupkg hash"):
            self.stage()

    def test_missing_runtime_notice(self):
        (self.runtime / "THIRD-PARTY-NOTICES.TXT").unlink()
        with self.assertRaisesRegex(ValueError, "absent or empty"):
            self.stage()

    def test_unofficial_runtime_restore(self):
        meta = legal.load(self.runtime / ".nupkg.metadata")
        meta["source"] = "https://unverified.example/feed"
        legal.write(self.runtime / ".nupkg.metadata", meta)
        with self.assertRaisesRegex(ValueError, "official NuGet"):
            self.stage()

    def test_environment_pack_is_not_effective(self):
        with (self.evidence / "packs.tsv").open("a") as f:
            f.write("Microsoft.WindowsDesktop.App.Runtime.win-x64|10.0.12|/not-an-input\n")
        self.stage()
        self.assertEqual(len(legal.load(self.output / legal.INVENTORY)["effectiveRuntimePacks"]), 1)

    def test_excluded_runtime_inputs_are_not_included(self):
        (self.evidence / "excluded.tsv").write_text(
            f"{self.runtime}/runtimes/win-x64/native/coreclr.dll|coreclr.dll\n")
        with self.assertRaisesRegex(ValueError, "No effective Microsoft.NETCore"):
            self.stage()

    def test_additional_effective_runtime_gets_separate_notices(self):
        name = "Microsoft.AspNetCore.App.Runtime.win-x64"
        directory = self.make_package(name, "10.0.100",
                                      {"LICENSE.TXT": b"separate license", "THIRD-PARTY-NOTICES.TXT": b"separate notices",
                                       "runtimes/win-x64/lib/net10.0/extra.dll": b"extra runtime"})
        with (self.evidence / "packs.tsv").open("a") as f:
            f.write(f"{name}|10.0.100|{directory}\n")
        with (self.evidence / "bundle.tsv").open("a") as f:
            f.write(f"{directory}/runtimes/win-x64/lib/net10.0/extra.dll|extra.dll\n")
        self.stage()
        self.assertEqual(len(legal.load(self.output / legal.INVENTORY)["effectiveRuntimePacks"]), 2)
        self.assertEqual((self.output / f"redistribution/dotnet/{name}/10.0.100/LICENSE.TXT").read_bytes(), b"separate license")

    def test_sbom_wrong_runtime_version_is_not_matched(self):
        self.stage()
        self.sbom()
        spdx = legal.load(self.output / legal.SPDX)
        spdx["packages"] = [
            {"SPDXID": "SPDXRef-runtime", "name": self.runtime_id, "versionInfo": "10.0.12",
             "licenseDeclared": "NOASSERTION"}]
        legal.write(self.output / legal.SPDX, spdx)
        before = (self.output / legal.SPDX).read_bytes()
        report = legal.reconcile(self.output)
        self.assertEqual(report["packages"][0]["status"], "unmatched-unverified")
        self.assertIsNone(report["packages"][0]["exactNuGetMetadata"])
        self.assertEqual(before, (self.output / legal.SPDX).read_bytes())

    def test_old_output_and_second_publish_refused(self):
        with self.assertRaisesRegex(ValueError, "must be empty"):
            legal.prepare(self.output)
        self.stage()
        with self.assertRaisesRegex(ValueError, "Old notices"):
            self.stage()

    def test_failure_after_publish_cannot_produce_checksums(self):
        self.stage(complete=False)
        self.sbom()
        self.assertFalse(legal.reconcile(self.output)["publishComplete"])
        with self.assertRaisesRegex(ValueError, "Publish incomplete"):
            legal.checksums(self.output)
        self.assertFalse((self.output / "SHA256SUMS.txt").exists())

    def test_unmatched_spdx_is_reported_blocked_without_modification(self):
        self.packaged()
        report = legal.load(self.output / legal.REPORT)
        self.assertEqual(report["publicReleaseGate"], "BLOCKED")
        self.assertEqual(report["noAssertionCount"], 2)
        self.assertEqual(report["packages"][1]["status"], "unmatched-unverified")
        self.assertEqual(report["packages"][0]["savLicenseEvidence"]["expression"], "MIT")
        with self.assertRaisesRegex(ValueError, "Public release BLOCKED"):
            legal.verify(self.output, public=True)

    def test_notice_missing_at_checksum_time(self):
        self.stage()
        self.sbom()
        legal.reconcile(self.output)
        (self.output / "redistribution/pgsqlparser/LICENSE").unlink()
        with self.assertRaises(ValueError):
            legal.checksums(self.output)

    def test_ci209_documentation_residue_is_rejected_even_with_spdx_coverage(self):
        self.stage()
        self.sbom()
        # Actual extra outputs of the CI #209 publish profile, before the fix.
        paths = ["querypact.xml", "Sav.Application.xml", "Sav.Domain.xml",
                 "Sav.Infrastructure.Config.xml", "Sav.Infrastructure.Postgres.xml",
                 "Sav.Infrastructure.Storage.xml"]
        spdx = legal.load(self.output / legal.SPDX)
        for relative in paths:
            (self.output / relative).write_bytes(b"private documentation fixture")
            spdx["files"].append({"fileName": "./" + relative, "checksums": [
                {"algorithm": "SHA256", "checksumValue": legal.digest(self.output / relative)}]})
        legal.write(self.output / legal.SPDX, spdx)
        before = (self.output / legal.SPDX).read_bytes()
        legal.reconcile(self.output)
        with self.assertRaises(ValueError) as error:
            legal.checksums(self.output)
        message = str(error.exception)
        self.assertIn("Unexpected files in publish output", message)
        self.assertIn("unexpected paths: " + json.dumps(sorted(paths)), message)
        self.assertNotIn("private documentation fixture", message)
        self.assertNotIn(str(self.output), message)
        self.assertFalse((self.output / "SHA256SUMS.txt").exists())
        self.assertEqual(before, (self.output / legal.SPDX).read_bytes())
        self.assertEqual(legal.load(self.output / legal.REPORT)["publicReleaseGate"], "BLOCKED")

    def test_unexpected_nested_paths_are_reported_safely_at_verification(self):
        self.packaged()
        relative = "scratch/private-output.txt"
        path = self.output / relative
        path.parent.mkdir()
        path.write_bytes(b"sensitive content must never appear in diagnostics")
        before = self.snapshot_output()
        with self.assertRaises(ValueError) as error:
            legal.verify(self.output)
        message = str(error.exception)
        self.assertIn("unexpected paths: " + json.dumps([relative]), message)
        self.assertNotIn("\n", message)
        self.assertNotIn("sensitive content", message)
        self.assertNotIn(str(self.output), message)
        self.assertEqual(before, self.snapshot_output())

    def test_inventory_diagnostic_escapes_control_characters(self):
        relative = "scratch/private\noutput\u001b.txt"
        with self.assertRaises(ValueError) as error:
            legal.require_file_inventory({relative}, set(), "Unexpected files")
        self.assertIn(json.dumps([relative]), str(error.exception))
        self.assertNotIn("\n", str(error.exception))
        self.assertNotIn("\u001b", str(error.exception))

    def test_bad_spdx_sidecar_cannot_reconcile(self):
        self.stage()
        self.sbom()
        (self.output / (legal.SPDX + ".sha256")).write_text("0" * 64)
        with self.assertRaisesRegex(ValueError, "manifest SHA256 sidecar"):
            legal.reconcile(self.output)

    def test_old_spdx_file_hash_does_not_match_candidate(self):
        self.stage()
        self.sbom()
        spdx = legal.load(self.output / legal.SPDX)
        for entry in spdx["files"]:
            if entry["fileName"] == "./querypact.exe":
                entry["checksums"][0]["checksumValue"] = "0" * 64
        legal.write(self.output / legal.SPDX, spdx)
        with self.assertRaisesRegex(ValueError, "does not match current candidate"):
            legal.reconcile(self.output)

    def test_tampered_checksum_or_executable(self):
        self.packaged()
        legal.verify(self.output)
        (self.output / "SHA256SUMS.txt").write_text("0" * 64 + "  querypact.exe\n")
        with self.assertRaisesRegex(ValueError, "Invalid checksum"):
            legal.verify(self.output)
        (self.output / "querypact.exe").write_bytes(b"rebuilt executable")
        with self.assertRaisesRegex(ValueError, "Executable changed"):
            legal.verify(self.output)

    def test_obsolete_runtime_notices_are_refused(self):
        self.packaged()
        obsolete = self.output / "redistribution/dotnet/old/1/LICENSE.TXT"
        obsolete.parent.mkdir(parents=True)
        obsolete.write_text("old runtime")
        with self.assertRaisesRegex(ValueError, "Obsolete/unexpected"):
            legal.verify(self.output)

    def test_stale_manifest_and_duplicate_checksums_refused(self):
        self.packaged()
        with self.assertRaisesRegex(ValueError, "Old checksums"):
            legal.checksums(self.output)
        with (self.output / "SHA256SUMS.txt").open("a") as f:
            f.write(f"{legal.digest(self.output / 'querypact.exe')}  querypact.exe\n")
        with self.assertRaisesRegex(ValueError, "Duplicate checksum"):
            legal.verify(self.output)
        spdx = legal.load(self.output / legal.SPDX)
        spdx["packages"][0]["versionInfo"] = "changed"
        legal.write(self.output / legal.SPDX, spdx)
        with self.assertRaisesRegex(ValueError, "Stale reconciliation"):
            legal.verify(self.output)


    def reviewed_fixture(self):
        fixture = BundleAuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.make_bundle()
        shutil.copyfile(fixture.path, self.output / "querypact.exe")
        directory = self.make_package("library", "1.0", {"lib/library.dll": b"library", "LICENSE": b"MIT fixture notice"})
        meta, _ = legal.package(directory, "library", "1.0")
        assets = legal.load(self.evidence / "project.assets.json")
        assets["libraries"]["library/1.0"] = {"type": "package", "path": "library/1.0"}
        legal.write(self.evidence / "project.assets.json", assets)
        with (self.evidence / "bundle.tsv").open("a") as f:
            f.write(f"{directory}/lib/library.dll|library.dll\n")
        reviewed = {"id": "library", "version": "1.0", "archiveEntry": "LICENSE",
                    "licenseExpression": "MIT", "sha256": legal.sha(b"MIT fixture notice"),
                    "nupkgSha256": meta["nupkgSha256"], "nuspecSha256": meta["nuspecSha256"],
                    "url": "https://example.invalid/synthetic-notice"}
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        return reviewed

    def test_reviewed_notice_is_byte_preserved_and_tampering_rejected(self):
        self.reviewed_fixture()
        self.stage()
        path = self.output / "redistribution/packages/library/1.0/LICENSE"
        self.assertEqual(path.read_bytes(), b"MIT fixture notice")
        path.write_bytes(b"altered")
        with self.assertRaisesRegex(ValueError, "notice hash"):
            legal.validate_notices(self.output)

    def test_reviewed_license_contradiction_and_incomplete_metadata_rejected(self):
        reviewed = self.reviewed_fixture()
        for expression in ("Apache-2.0", None):
            reviewed["licenseExpression"] = expression
            legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
            with self.assertRaisesRegex(ValueError, "contradiction"):
                self.stage()
            shutil.rmtree(self.output / "redistribution")

    def test_reviewed_notice_false_hash_and_unverified_payload_rejected(self):
        reviewed = self.reviewed_fixture()
        reviewed["sha256"] = "0" * 64
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        with self.assertRaisesRegex(ValueError, "notice hash mismatch"):
            self.stage()
        shutil.rmtree(self.output / "redistribution")
        reviewed["sha256"] = legal.sha(b"MIT fixture notice")
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        cache_dll = self.cache / "library/1.0/lib/library.dll"
        cache_dll.write_bytes(b"unverified payload")
        with self.assertRaisesRegex(ValueError, "Bundle payload hashes differ"):
            self.stage()


    def test_reviewed_cached_payload_must_match_archive_even_if_bundled(self):
        self.reviewed_fixture()
        cached = self.cache / "library/1.0/lib/library.dll"
        cached.write_bytes(b"forged!")
        executable = self.output / "querypact.exe"
        executable.write_bytes(executable.read_bytes().replace(b"library", b"forged!", 1))
        with self.assertRaisesRegex(ValueError, "differs from exact source archive"):
            self.stage()

    def test_excluded_reviewed_package_gets_no_attribution(self):
        self.reviewed_fixture()
        cached = self.cache / "library/1.0/lib/library.dll"
        (self.evidence / "excluded.tsv").write_text(f"{cached}|library.dll\n")
        self.stage()
        inventory = legal.load(self.output / legal.INVENTORY)
        self.assertEqual(inventory["reviewedPackageNotices"], [])
        self.assertFalse((self.output / "redistribution/packages").exists())

    def test_missing_reviewed_selection_cannot_validate(self):
        self.reviewed_fixture()
        self.stage()
        inventory = legal.load(self.output / legal.INVENTORY)
        inventory["reviewedPackageNotices"] = []
        legal.write(self.output / legal.INVENTORY, inventory)
        with self.assertRaisesRegex(ValueError, "selection incomplete"):
            legal.validate_notices(self.output)


    def test_false_physical_report_cannot_receive_checksums(self):
        self.stage()
        self.sbom()
        legal.reconcile(self.output)
        report = legal.load(self.output / legal.REPORT)
        report["coverageAudit"]["physicalBundle"]["hashMismatches"] = ["fake.dll"]
        legal.write(self.output / legal.REPORT, report)
        with self.assertRaisesRegex(ValueError, "physical reconciliation"):
            legal.checksums(self.output)
        self.assertFalse((self.output / "SHA256SUMS.txt").exists())

    def additional_fixture(self, upstream=False):
        reviewed = self.reviewed_fixture()
        repository = {"type": "git", "url": "https://github.com/vendor/library",
                      "commit": "a" * 40}
        data = b"Additional original notice\\r\\n\r\n"
        directory = self.make_package("library", "1.0", {
            "lib/library.dll": b"library", "LICENSE": b"MIT fixture notice",
            "THIRD-PARTY-NOTICES.txt": data}, repository=repository)
        meta, _ = legal.package(directory, "library", "1.0")
        reviewed.update(nupkgSha256=meta["nupkgSha256"], nuspecSha256=meta["nuspecSha256"])
        additional = {"archiveEntry": "THIRD-PARTY-NOTICES.txt", "sha256": legal.sha(data),
                      "sourceType": "upstream" if upstream else "archive",
                      "obligation": "Preserve original attribution", "applicability": "Compiled fixture code"}
        if upstream:
            additional["upstream"] = {
                "repository": repository, "path": "THIRD-PARTY-NOTICES.txt",
                "url": "https://raw.githubusercontent.com/vendor/library/" + "a" * 40 + "/THIRD-PARTY-NOTICES.txt",
                "cachedPath": "redistribution/upstream/fixture/THIRD-PARTY-NOTICES.txt"}
            source = self.repo / additional["upstream"]["cachedPath"]
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(data)
        reviewed["additionalNotices"] = [additional]
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        return reviewed, additional, data

    def test_runtime_additional_notice_wrong_version_and_attribution_rejected(self):
        self.stage()
        original = legal.load(self.output / legal.INVENTORY)
        for field, value in (("version", "10.0.1"), ("component", "other"), ("source", "other")):
            inventory = json.loads(json.dumps(original))
            notice = next(n for n in inventory["notices"] if n.get("archiveEntry") == "THIRD-PARTY-NOTICES.TXT")
            notice[field] = value
            legal.write(self.output / legal.INVENTORY, inventory)
            with self.assertRaisesRegex(ValueError, "Runtime notice attribution mismatch"):
                legal.validate_notices(self.output)

    def test_native_notice_contradictory_attribution_rejected(self):
        self.stage()
        inventory = legal.load(self.output / legal.INVENTORY)
        inventory["notices"][0]["revision"] = "wrong"
        legal.write(self.output / legal.INVENTORY, inventory)
        with self.assertRaisesRegex(ValueError, "Native notice attribution mismatch"):
            legal.validate_notices(self.output)

    def test_additional_archive_notice_bytes_checksums_and_attribution(self):
        reviewed, additional, data = self.additional_fixture()
        self.stage()
        path = legal.notice_path({**reviewed, **additional})
        self.assertEqual((self.output / path).read_bytes(), data)
        inventory = legal.load(self.output / legal.INVENTORY)
        self.assertEqual(len(inventory["reviewedPackageNotices"]), 2)
        self.sbom()
        legal.reconcile(self.output)
        legal.checksums(self.output)
        self.assertIn(path, (self.output / "SHA256SUMS.txt").read_text())
        (self.output / path).write_bytes(data + b"changed")
        with self.assertRaisesRegex(ValueError, "notice hash"):
            legal.verify(self.output)

    def test_additional_upstream_allowed_with_archived_primary_and_original_bytes(self):
        reviewed, additional, data = self.additional_fixture(upstream=True)
        self.stage()
        self.assertEqual((self.output / legal.notice_path({**reviewed, **additional})).read_bytes(), data)

    def test_additional_missing_and_altered_source_rejected(self):
        reviewed, additional, data = self.additional_fixture(upstream=True)
        source = self.repo / additional["upstream"]["cachedPath"]
        source.unlink()
        with self.assertRaises(ValueError):
            self.stage()
        source.write_bytes(data + b"altered")
        with self.assertRaisesRegex(ValueError, "notice hash"):
            self.stage()

    def test_additional_wrong_version_and_contradictory_identity_rejected(self):
        reviewed, additional, _ = self.additional_fixture()
        for field, value in (("version", "2.0"), ("id", "other"), ("nupkgSha256", "0" * 64)):
            additional[field] = value
            legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
            with self.assertRaisesRegex(ValueError, "attribution contradiction"):
                self.stage()
            del additional[field]

    def test_additional_wrong_upstream_revision_rejected(self):
        reviewed, additional, _ = self.additional_fixture(upstream=True)
        additional["upstream"]["repository"]["commit"] = "b" * 40
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        with self.assertRaisesRegex(ValueError, "contradicts exact nuspec"):
            self.stage()

    def test_additional_absence_and_attribution_tampering_at_validation_rejected(self):
        self.additional_fixture()
        self.stage()
        inventory = legal.load(self.output / legal.INVENTORY)
        original = json.loads(json.dumps(inventory))
        inventory["reviewedPackageNotices"].pop()
        legal.write(self.output / legal.INVENTORY, inventory)
        with self.assertRaisesRegex(ValueError, "selection incomplete"):
            legal.validate_notices(self.output)
        notice = next(n for n in original["notices"] if n.get("archiveEntry") == "THIRD-PARTY-NOTICES.txt")
        notice["component"] = "other"
        legal.write(self.output / legal.INVENTORY, original)
        with self.assertRaisesRegex(ValueError, "attribution mismatch"):
            legal.validate_notices(self.output)

    def test_additional_duplicate_path_and_incomplete_selection_rejected(self):
        reviewed, additional, _ = self.additional_fixture()
        additional["archiveEntry"] = "LICENSE"
        with self.assertRaisesRegex(ValueError, "Duplicate reviewed notice path"):
            legal.reviewed_texts([reviewed])
        del additional["applicability"]
        with self.assertRaisesRegex(ValueError, "Incomplete additional"):
            legal.reviewed_texts([reviewed])

    def containers_reference_fixture_data(self):
        # Real immutable notice chain, synthetic package/bundle bytes. This
        # exercises staging without claiming a reproduced vendor assembly.
        policy = legal.load(self.repo / legal.PACKAGE_NOTICES)["packages"]
        reviewed = next(p for p in policy if p["id"].lower() == "testcontainers")
        fixture = BundleAuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.make_bundle()
        shutil.copyfile(fixture.path, self.output / "querypact.exe")
        repository = reviewed["additionalNotices"][0]["upstream"]["repository"]
        directory = self.make_package(reviewed["id"], reviewed["version"],
                                      {"lib/library.dll": b"library", "LICENSE": b"MIT fixture notice"},
                                      repository=repository)
        meta, _ = legal.package(directory, reviewed["id"], reviewed["version"])
        reviewed.update(nupkgSha256=meta["nupkgSha256"], nuspecSha256=meta["nuspecSha256"],
                        sha256=legal.sha(b"MIT fixture notice"))
        assets = legal.load(self.evidence / "project.assets.json")
        assets["libraries"]["Testcontainers/4.14.0"] = {
            "type": "package", "path": "testcontainers/4.14.0"}
        legal.write(self.evidence / "project.assets.json", assets)
        with (self.evidence / "bundle.tsv").open("a") as stream:
            stream.write(f"{directory}/lib/library.dll|library.dll\n")
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        return reviewed

    def test_testcontainers_reference_originals_staging_and_checksums(self):
        reviewed = self.containers_reference_fixture_data()
        self.packaged()
        for additional in reviewed["additionalNotices"]:
            path = legal.notice_path({**reviewed, **additional})
            self.assertEqual(legal.digest(self.output / path), additional["sha256"])
            self.assertIn(path, (self.output / "SHA256SUMS.txt").read_text())
        inventory = legal.load(self.output / legal.INVENTORY)
        self.assertEqual(len(inventory["reviewedPackageNotices"]), 3)
        self.assertTrue(all(p["id"] == "Testcontainers" for p in inventory["reviewedPackageNotices"]))

    def test_testcontainers_reference_tampered_origin_refused(self):
        reviewed = self.containers_reference_fixture_data()
        additional = reviewed["additionalNotices"][1]
        anchor = self.repo / additional["upstream"]["cachedPath"]
        # Even a policy hash updated to match altered bytes cannot replace the
        # immutable origin link with an unrelated revision.
        anchor.write_bytes(anchor.read_bytes().replace(b"8c942b0459dfdcc5b6685581dd0a5a470f615bff", b"0" * 40))
        additional["upstream"]["sha256"] = legal.digest(anchor)
        reviewed["additionalNotices"][0]["sha256"] = legal.digest(anchor)
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        with self.assertRaisesRegex(ValueError, "lacks exact source link"):
            self.stage()

    def test_testcontainers_reference_false_staged_component_refused(self):
        self.containers_reference_fixture_data()
        self.stage()
        inventory = legal.load(self.output / legal.INVENTORY)
        notice = next(n for n in inventory["notices"] if n["path"].endswith("distribution-reference-LICENSE"))
        notice["component"] = "Testcontainers.PostgreSql"
        legal.write(self.output / legal.INVENTORY, inventory)
        with self.assertRaisesRegex(ValueError, "attribution mismatch"):
            legal.validate_notices(self.output)

    def linked_fixture(self):
        reviewed, additional, _ = self.additional_fixture(upstream=True)
        repository = {"type": "git", "url": "https://github.com/original/source", "commit": "b" * 40}
        link = repository["url"] + "/blob/" + repository["commit"] + "/src/Pool.cs"
        anchor = self.repo / additional["upstream"]["cachedPath"]
        anchor.write_bytes(("Adapted from " + link + "\r\n").encode())
        additional["upstream"]["sha256"] = legal.digest(anchor)
        additional["sourceType"] = "linked"
        original = self.repo / "redistribution/upstream/original/Pool.cs"
        original.parent.mkdir(parents=True, exist_ok=True)
        original.write_bytes(b"Original source and attribution\r\n")
        text = self.repo / "redistribution/upstream/original/LICENSE.txt"
        text.write_bytes(b"Original MIT copyright and permission\r\n")
        additional["linkedText"] = {
            "repository": repository, "path": "LICENSE.txt",
            "url": "https://raw.githubusercontent.com/original/source/" + "b" * 40 + "/LICENSE.txt",
            "cachedPath": text.relative_to(self.repo).as_posix(),
            "reference": {"path": "src/Pool.cs", "sha256": legal.digest(original),
                          "cachedPath": original.relative_to(self.repo).as_posix()}}
        additional["sha256"] = legal.digest(text)
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        return reviewed, additional, anchor, original, text

    def test_linked_original_bytes_attribution_and_checksums(self):
        reviewed, additional, _, _, text = self.linked_fixture()
        self.stage()
        path = legal.notice_path({**reviewed, **additional})
        self.assertEqual((self.output / path).read_bytes(), text.read_bytes())
        inventory = legal.load(self.output / legal.INVENTORY)
        notice = next(n for n in inventory["notices"] if n["path"] == path)
        self.assertEqual(notice["source"], additional["linkedText"]["url"])
        self.assertEqual(notice["component"], reviewed["id"])
        self.sbom()
        legal.reconcile(self.output)
        legal.checksums(self.output)
        self.assertIn(path, (self.output / "SHA256SUMS.txt").read_text())

    def test_linked_missing_or_tampered_chain_sources_rejected(self):
        _, _, anchor, original, text = self.linked_fixture()
        for source in (anchor, original, text):
            data = source.read_bytes()
            for tamper in (None, data + b"tampered"):
                shutil.rmtree(self.output / "redistribution", ignore_errors=True)
                if tamper is None:
                    source.unlink()
                else:
                    source.write_bytes(tamper)
                with self.assertRaises(ValueError):
                    self.stage()
                source.write_bytes(data)

    def test_linked_exact_link_required_even_with_matching_anchor_hash(self):
        reviewed, additional, anchor, _, _ = self.linked_fixture()
        anchor.write_bytes(b"An unrelated MIT source\r\n")
        additional["upstream"]["sha256"] = legal.digest(anchor)
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        with self.assertRaisesRegex(ValueError, "lacks exact source link"):
            self.stage()

    def test_linked_revision_url_and_paths_rejected(self):
        reviewed, additional, _, _, _ = self.linked_fixture()
        row = legal.reviewed_texts([reviewed])[1]
        meta = {"repository": additional["upstream"]["repository"]}
        target = additional["linkedText"]
        for obj, field, bad in ((target["repository"], "commit", "main"),
                                (target, "url", "https://example.invalid/LICENSE"),
                                (target, "path", "../LICENSE"),
                                (target, "cachedPath", "../LICENSE"),
                                (target["reference"], "path", "../Pool.cs"),
                                (target["reference"], "cachedPath", "../Pool.cs"),
                                (target["reference"], "sha256", "invalid"),
                                (additional["upstream"], "sha256", "invalid")):
            previous = obj[field]
            obj[field] = bad
            with self.assertRaises(ValueError):
                legal.notice_source(row, meta)
            obj[field] = previous

    def test_linked_nuspec_anchor_contradiction_rejected(self):
        reviewed, additional, _, _, _ = self.linked_fixture()
        additional["upstream"]["repository"]["commit"] = "c" * 40
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        with self.assertRaisesRegex(ValueError, "contradicts exact nuspec"):
            self.stage()

    def test_linked_incomplete_evidence_and_primary_selection_rejected(self):
        reviewed, additional, _, _, _ = self.linked_fixture()
        row = legal.reviewed_texts([reviewed])[1]
        meta = {"repository": additional["upstream"]["repository"]}
        for obj, field in ((row, "linkedText"), (row["linkedText"], "reference"),
                           (row["linkedText"]["reference"], "cachedPath")):
            value = obj.pop(field)
            with self.assertRaisesRegex(ValueError, "Incomplete linked"):
                legal.notice_source(row, meta)
            obj[field] = value
        row.pop("noticeRole")
        with self.assertRaisesRegex(ValueError, "Linked primary"):
            legal.notice_source(row, meta)

    def test_linked_staged_tampering_and_missing_selection_rejected(self):
        reviewed, additional, _, _, _ = self.linked_fixture()
        self.stage()
        path = self.output / legal.notice_path({**reviewed, **additional})
        data = path.read_bytes()
        path.write_bytes(data + b"tampered")
        with self.assertRaisesRegex(ValueError, "notice hash"):
            legal.validate_notices(self.output, require_complete=False)
        path.write_bytes(data)
        inventory = legal.load(self.output / legal.INVENTORY)
        inventory["reviewedPackageNotices"].pop()
        legal.write(self.output / legal.INVENTORY, inventory)
        with self.assertRaisesRegex(ValueError, "selection incomplete"):
            legal.validate_notices(self.output, require_complete=False)

    def referenced_fixture(self):
        reviewed, additional, _ = self.additional_fixture(upstream=True)
        anchor = self.repo / additional["upstream"]["cachedPath"]
        anchor.write_bytes(b"Original header: http://www.apache.org/licenses/LICENSE-2.0\r\n")
        additional["upstream"]["sha256"] = legal.digest(anchor)
        additional["sourceType"] = "referenced"
        additional["archiveEntry"] = "Apache-2.0.txt"
        additional["referencedText"] = {
            "url": "https://www.apache.org/licenses/LICENSE-2.0.txt",
            "cachedPath": "redistribution/upstream/fixture/Apache-2.0.txt"}
        license_path = self.repo / additional["referencedText"]["cachedPath"]
        license_path.write_bytes(b"Original referenced license fixture\r\n")
        additional["sha256"] = legal.digest(license_path)
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        return reviewed, additional, anchor, license_path

    def test_referenced_license_preserves_bytes_and_checksums(self):
        reviewed, additional, _, license_path = self.referenced_fixture()
        self.stage()
        self.assertEqual((self.output / legal.notice_path({**reviewed, **additional})).read_bytes(),
                         license_path.read_bytes())
        self.sbom()
        legal.reconcile(self.output)
        legal.checksums(self.output)
        legal.verify(self.output)

    def test_referenced_license_missing_or_altered_anchor_and_license_rejected(self):
        _, _, anchor, license_path = self.referenced_fixture()
        data = anchor.read_bytes()
        anchor.write_bytes(data + b"changed")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.stage()
        anchor.write_bytes(data)
        original = license_path.read_bytes()
        license_path.unlink()
        with self.assertRaises(ValueError):
            self.stage()
        license_path.write_bytes(original + b"changed")
        with self.assertRaisesRegex(ValueError, "notice hash"):
            self.stage()

    def test_referenced_license_arbitrary_url_or_revision_rejected(self):
        reviewed, additional, _, _ = self.referenced_fixture()
        additional["referencedText"]["url"] = "https://example.invalid/LICENSE"
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        with self.assertRaisesRegex(ValueError, "Unsupported referenced"):
            self.stage()
        additional["referencedText"]["url"] = "https://www.apache.org/licenses/LICENSE-2.0.txt"
        additional["upstream"]["repository"]["commit"] = "c" * 40
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})
        with self.assertRaisesRegex(ValueError, "contradicts exact nuspec"):
            self.stage()

    def upstream_fixture(self):
        reviewed = self.reviewed_fixture()
        repository = {"type": "git", "url": "https://github.com/vendor/library", "commit": "a" * 40}
        directory = self.make_package("library", "1.0", {"lib/library.dll": b"library"},
                                      repository=repository)
        meta, _ = legal.package(directory, "library", "1.0")
        reviewed.update(sourceType="upstream", nupkgSha256=meta["nupkgSha256"],
                        nuspecSha256=meta["nuspecSha256"])
        reviewed["upstream"] = {"repository": repository, "path": "LICENSE",
                                "url": "https://raw.githubusercontent.com/vendor/library/" + "a" * 40 + "/LICENSE",
                                "cachedPath": "redistribution/upstream/fixture/LICENSE"}
        source = self.repo / reviewed["upstream"]["cachedPath"]
        source.parent.mkdir(parents=True)
        source.write_bytes(b"MIT fixture notice")
        self.save_reviewed(reviewed)
        return reviewed, source

    def save_reviewed(self, reviewed):
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed]})

    def test_upstream_notice_preserves_bytes_and_individual_provenance(self):
        reviewed, source = self.upstream_fixture()
        self.stage()
        self.assertEqual((self.output / legal.notice_path(reviewed)).read_bytes(), source.read_bytes())
        inventory = legal.load(self.output / legal.INVENTORY)
        notice = next(n for n in inventory["notices"] if n["component"] == "library")
        self.assertEqual(notice["source"], reviewed["upstream"]["url"])
        self.sbom()
        self.assertEqual(legal.reconcile(self.output)["publicReleaseGate"], "BLOCKED")

    def test_upstream_same_mit_different_repository_or_commit_rejected(self):
        reviewed, _ = self.upstream_fixture()
        for field, value in (("url", "https://github.com/other/library"), ("commit", "b" * 40)):
            original = reviewed["upstream"]["repository"][field]
            reviewed["upstream"]["repository"][field] = value
            self.save_reviewed(reviewed)
            with self.assertRaisesRegex(ValueError, "contradicts exact nuspec"):
                self.stage()
            reviewed["upstream"]["repository"][field] = original
            shutil.rmtree(self.output / "redistribution")

    def test_upstream_unpinned_or_false_source_url_rejected(self):
        reviewed, _ = self.upstream_fixture()
        reviewed["upstream"]["url"] = "https://raw.githubusercontent.com/vendor/library/main/LICENSE"
        self.save_reviewed(reviewed)
        with self.assertRaisesRegex(ValueError, "URL/revision mismatch"):
            self.stage()

    def test_upstream_unpinned_nuspec_revision_rejected(self):
        reviewed, _ = self.upstream_fixture()
        reviewed["upstream"]["repository"]["commit"] = "main"
        directory = self.make_package("library", "1.0", {"lib/library.dll": b"library"},
                                      repository=reviewed["upstream"]["repository"])
        meta, _ = legal.package(directory, "library", "1.0")
        reviewed.update(nupkgSha256=meta["nupkgSha256"], nuspecSha256=meta["nuspecSha256"])
        self.save_reviewed(reviewed)
        with self.assertRaisesRegex(ValueError, "immutable Git commit"):
            self.stage()

    def test_upstream_missing_nuspec_repository_rejected(self):
        reviewed, _ = self.upstream_fixture()
        directory = self.make_package("library", "1.0", {"lib/library.dll": b"library"})
        meta, _ = legal.package(directory, "library", "1.0")
        reviewed.update(nupkgSha256=meta["nupkgSha256"], nuspecSha256=meta["nuspecSha256"])
        self.save_reviewed(reviewed)
        with self.assertRaisesRegex(ValueError, "contradicts exact nuspec"):
            self.stage()

    def test_upstream_missing_blank_or_forged_text_rejected(self):
        reviewed, source = self.upstream_fixture()
        for data in (None, b" \r\n", b"another MIT copyright"):
            if data is None:
                source.unlink()
            else:
                source.write_bytes(data)
            with self.assertRaises((ValueError, OSError)):
                self.stage()
            shutil.rmtree(self.output / "redistribution")

    def test_upstream_false_archive_or_nuspec_hash_rejected(self):
        reviewed, _ = self.upstream_fixture()
        for field in ("nupkgSha256", "nuspecSha256"):
            original = reviewed[field]
            reviewed[field] = "0" * 64
            self.save_reviewed(reviewed)
            with self.assertRaisesRegex(ValueError, "license/source contradiction"):
                self.stage()
            reviewed[field] = original
            shutil.rmtree(self.output / "redistribution")

    def test_upstream_different_version_gets_no_substitution(self):
        reviewed, _ = self.upstream_fixture()
        reviewed["version"] = "2.0"
        self.save_reviewed(reviewed)
        self.stage()
        self.assertEqual(legal.load(self.output / legal.INVENTORY)["reviewedPackageNotices"], [])

    def test_upstream_inventory_attribution_tampering_rejected(self):
        self.upstream_fixture()
        self.stage()
        inventory = legal.load(self.output / legal.INVENTORY)
        next(n for n in inventory["notices"] if n["component"] == "library")["source"] = "https://example.invalid/MIT"
        legal.write(self.output / legal.INVENTORY, inventory)
        with self.assertRaisesRegex(ValueError, "attribution mismatch"):
            legal.validate_notices(self.output)

    def test_duplicate_reviewed_identity_rejected(self):
        reviewed, _ = self.upstream_fixture()
        legal.write(self.repo / legal.PACKAGE_NOTICES, {"packages": [reviewed, reviewed]})
        with self.assertRaisesRegex(ValueError, "Duplicate reviewed package identity"):
            self.stage()

    def test_upstream_unsafe_source_path_rejected(self):
        reviewed, _ = self.upstream_fixture()
        reviewed["upstream"]["cachedPath"] = "../LICENSE"
        self.save_reviewed(reviewed)
        with self.assertRaisesRegex(ValueError, "Invalid inventory path"):
            self.stage()

    def test_upstream_fallback_refused_when_archive_contains_primary_text(self):
        reviewed, _ = self.upstream_fixture()
        executable = (self.output / "querypact.exe").read_bytes()
        for entry in ("LICENSE", "docs/LICENSE", "licenses/COPYING.txt"):
            with self.subTest(entry=entry):
                shutil.rmtree(self.output)
                self.output.mkdir()
                (self.output / "querypact.exe").write_bytes(executable)
                files = {"lib/library.dll": b"library", entry: b"archive text"}
                directory = self.make_package("library", "1.0", files,
                                               repository=reviewed["upstream"]["repository"])
                meta, _ = legal.package(directory, "library", "1.0")
                reviewed.update(nupkgSha256=meta["nupkgSha256"], nuspecSha256=meta["nuspecSha256"])
                self.save_reviewed(reviewed)
                with self.assertRaisesRegex(ValueError, "upstream fallback refused"):
                    self.stage()

    def test_upstream_fallback_allowed_when_archive_has_no_primary_text(self):
        reviewed, source = self.upstream_fixture()
        directory = self.make_package("library", "1.0", {"lib/library.dll": b"library", "docs/": None},
                                      repository=reviewed["upstream"]["repository"])
        meta, _ = legal.package(directory, "library", "1.0")
        reviewed.update(nupkgSha256=meta["nupkgSha256"], nuspecSha256=meta["nuspecSha256"])
        self.save_reviewed(reviewed)
        self.stage()
        self.assertEqual((self.output / legal.notice_path(reviewed)).read_bytes(), source.read_bytes())

    def test_upstream_fallback_rejects_unsafe_or_ambiguous_zip_paths(self):
        reviewed, _ = self.upstream_fixture()
        executable = (self.output / "querypact.exe").read_bytes()
        for entries in (("../LICENSE",), ("docs//LICENSE",), ("docs/LICENSE", "DOCS/license")):
            with self.subTest(entries=entries):
                shutil.rmtree(self.output)
                self.output.mkdir()
                (self.output / "querypact.exe").write_bytes(executable)
                files = {"lib/library.dll": b"library"}
                files.update({entry: b"archive text" for entry in entries})
                directory = self.make_package("library", "1.0", files,
                                               repository=reviewed["upstream"]["repository"])
                meta, _ = legal.package(directory, "library", "1.0")
                reviewed.update(nupkgSha256=meta["nupkgSha256"], nuspecSha256=meta["nuspecSha256"])
                self.save_reviewed(reviewed)
                with self.assertRaisesRegex(ValueError, "Unsafe or ambiguous ZIP path|Duplicate or ambiguous ZIP path"):
                    self.stage()


class BundleAuditTests(unittest.TestCase):
    def setUp(self):
        import release_bundle
        self.bundle = release_bundle
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "querypact.exe"

    def make_bundle(self, name="library.dll", version=6, compressed=0, duplicate=False, payloads=None):
        import struct
        def string(value):
            raw = value.encode()
            self.assertLess(len(raw), 128)
            return bytes([len(raw)]) + raw
        data = bytearray(128)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\0\0"
        marker = 80
        data[marker:marker + 32] = self.bundle.SIGNATURE
        entries = []
        payloads = payloads or [(1, name, b"library"), (3, "querypact.deps.json", b"{}"),
                                (4, "querypact.runtimeconfig.json", b"{}")]
        for kind, relative, payload in payloads:
            offset = len(data)
            data.extend(payload)
            entries.append((offset, len(payload), compressed, kind, relative))
        header = len(data)
        struct.pack_into("<q", data, marker - 8, header)
        data.extend(struct.pack("<IIi", version, 0, len(entries) + int(duplicate)))
        data.extend(string("bundle-id"))
        data.extend(struct.pack("<qqqqQ", next(e[0] for e in entries if e[3] == 3), 2, next(e[0] for e in entries if e[3] == 4), 2, 0))
        for offset, size, comp, kind, relative in entries + (entries[:1] if duplicate else []):
            data.extend(struct.pack("<qqqB", offset, size, comp, kind))
            data.extend(string(relative))
        self.path.write_bytes(data)
        rows = [{"bundlePath": r[4], "sha256": legal.sha(payload[2])}
                for r, payload in zip(entries, payloads)]
        rows[0].update(package="library", version="1.0")
        return {"exeSha256": legal.digest(self.path), "bundleInputs": rows,
                "packages": [{"id": "library", "version": "1.0", "license": None}],
                "effectiveRuntimePacks": []}

    def test_physical_presence_and_missing_spdx(self):
        evidence = self.make_bundle()
        physical = self.bundle.coverage(self.path, evidence)
        report = self.bundle.classify({"packages": []}, evidence, physical)
        self.assertEqual(report["missingSpdxCount"], 1)
        self.assertEqual(report["presenceCounts"], {"physically-verified": 1})
        self.assertEqual(report["publicReleaseGate"], "BLOCKED")
        self.assertEqual(physical["hashMismatches"], [])

    def test_divergent_version_is_not_attributed(self):
        evidence = self.make_bundle()
        report = self.bundle.classify({"packages": [{"name": "library", "versionInfo": "2.0",
                                    "SPDXID": "SPDXRef-lib", "licenseDeclared": "NOASSERTION"}]},
                                     evidence, self.bundle.coverage(self.path, evidence))
        self.assertEqual(report["packages"][0]["presence"], "unknown")
        self.assertEqual(report["missingSpdxCount"], 1)

    def test_missing_input_and_false_hash_remain_gaps(self):
        evidence = self.make_bundle()
        evidence["bundleInputs"][0]["sha256"] = "0" * 64
        evidence["bundleInputs"].append({"bundlePath": "absent.dll", "sha256": "0" * 64})
        result = self.bundle.coverage(self.path, evidence)
        self.assertEqual(result["hashMismatches"], ["library.dll"])
        self.assertEqual(result["inputsWithoutEntry"], ["absent.dll"])
        report = self.bundle.classify({"packages": []}, evidence, result)
        self.assertEqual(report["packages"][0]["presence"], "effective-input-not-physically-verified")

    def test_unowned_entry_is_reported(self):
        evidence = self.make_bundle()
        evidence["bundleInputs"].pop(0)
        self.assertEqual(len(self.bundle.coverage(self.path, evidence)["entriesWithoutInput"]), 1)

    def test_resolved_package_does_not_prove_build_exclusion(self):
        evidence = self.make_bundle()
        evidence["bundleInputs"][0].pop("package")
        evidence["bundleInputs"][0].pop("version")
        report = self.bundle.classify({"packages": [{"name": "library", "versionInfo": "1.0",
                                    "SPDXID": "SPDXRef-lib"}]}, evidence,
                                     self.bundle.coverage(self.path, evidence))
        self.assertEqual(report["packages"][0]["presence"], "resolved-without-effective-input")

    def test_no_speculative_relationships_or_license_resolution(self):
        evidence = self.make_bundle()
        spdx = {"packages": [{"name": "library", "versionInfo": "1.0", "SPDXID": "SPDXRef-lib",
                              "licenseDeclared": "NOASSERTION"}], "relationships": []}
        before = json.dumps(spdx)
        report = self.bundle.classify(spdx, evidence, self.bundle.coverage(self.path, evidence))
        self.assertEqual(json.dumps(spdx), before)
        self.assertNotIn("relationships", report)
        self.assertEqual(report["noAssertionCount"], 1)

    def test_duplicate_and_incomplete_owners_rejected(self):
        for error in ("duplicate", "owner"):
            evidence = self.make_bundle()
            if error == "duplicate":
                evidence["bundleInputs"].append(evidence["bundleInputs"][0])
            else:
                evidence["bundleInputs"][0].pop("version")
            with self.assertRaises(ValueError):
                self.bundle.coverage(self.path, evidence)

    def test_malicious_paths_rejected(self):
        for name in ("../evil.dll", "/evil.dll", "C:/evil.dll", "a\\b", "a//b", "a/./b", "a\nevil"):
            self.make_bundle(name=name)
            with self.assertRaises(ValueError):
                self.bundle.inspect(self.path)
            with self.assertRaises(ValueError):
                legal.safe_path(self.path.parent, name)

    def test_unsupported_formats_duplicates_and_truncation_rejected(self):
        for params in ({"version": 7}, {"compressed": 1}, {"duplicate": True}):
            self.make_bundle(**params)
            with self.assertRaises(ValueError):
                self.bundle.inspect(self.path)
        self.make_bundle()
        self.path.write_bytes(self.path.read_bytes()[:-2])
        with self.assertRaises(ValueError):
            self.bundle.inspect(self.path)

    def test_executable_hash_and_out_of_bounds_payload_rejected(self):
        import struct
        evidence = self.make_bundle()
        evidence["exeSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.bundle.coverage(self.path, evidence)
        data = bytearray(self.path.read_bytes())
        header = struct.unpack_from("<q", data, 72)[0]
        struct.pack_into("<q", data, header + 12 + 10 + 40, len(data) + 1)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "payload bounds"):
            self.bundle.inspect(self.path)


class SbomEnrichmentTests(unittest.TestCase):
    """Real format, synthetic bytes: source checks and unauthorized transformations."""
    def setUp(self):
        import release_sbom as sbom
        self.sbom_tool = sbom
        fixture = ReleaseLicenseTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.output = fixture.output
        self.cache = fixture.cache
        extra = fixture.make_package("Example.Package", "1.2.3", {"lib/net10.0/Example.dll": b"example bytes"})
        assets = legal.load(fixture.evidence / "project.assets.json")
        assets["libraries"]["Example.Package/1.2.3"] = {"type": "package", "path": "example.package/1.2.3"}
        legal.write(fixture.evidence / "project.assets.json", assets)
        with (fixture.evidence / "bundle.tsv").open("a") as stream:
            stream.write(f"{extra}/lib/net10.0/Example.dll|Example.dll\n")
            for filename in ("querypact.deps.json", "querypact.runtimeconfig.json"):
                (fixture.evidence / filename).write_bytes(b"{}")
                stream.write(f"{fixture.evidence / filename}|{filename}\n")
        bundle = BundleAuditTests()
        bundle.setUp()
        self.addCleanup(bundle.doCleanups)
        bundle.make_bundle(payloads=[(2, "coreclr.dll", b"runtime fixture"),
                                    (2, "libpg_query.dll", fixture.dll),
                                    (1, "Example.dll", b"example bytes"),
                                    (3, "querypact.deps.json", b"{}"),
                                    (4, "querypact.runtimeconfig.json", b"{}")])
        shutil.copyfile(bundle.path, self.output / "querypact.exe")
        fixture.stage()
        fixture.sbom()
        document = legal.load(self.output / legal.SPDX)
        document.update(dataLicense="CC0-1.0", SPDXID="SPDXRef-DOCUMENT", name="QueryPact fixture",
                        documentNamespace="https://example.org/spdx/fixture",
                        creationInfo={"created": "2026-10-04T10:07:35Z", "creators": ["Tool: Microsoft.SBOMTool-4.1.5"]},
                        documentDescribes=["SPDXRef-QueryPact"], externalDocumentRefs=[],
                        relationships=[{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                        "relatedSpdxElement": "SPDXRef-QueryPact"}])
        document["packages"].append({"SPDXID": "SPDXRef-example", "name": "Example.Package", "versionInfo": "1.2.3",
                                     "licenseDeclared": "NOASSERTION", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                     "referenceType": "purl", "referenceLocator": "pkg:nuget/Example.Package@1.2.3"}]})
        for row in document["packages"]:
            row.update(downloadLocation="NOASSERTION", filesAnalyzed=False, licenseConcluded="NOASSERTION", copyrightText="NOASSERTION")
        for row in document["files"]:
            row.update(SPDXID="SPDXRef-File-" + legal.sha(row["fileName"].encode()), licenseConcluded="NOASSERTION",
                       copyrightText="NOASSERTION", licenseInfoInFiles=["NOASSERTION"])
            row["checksums"].append({"algorithm": "SHA1", "checksumValue": hashlib.sha1(
                (self.output / row["fileName"].removeprefix("./")).read_bytes()).hexdigest()})
        self.save_manifest(document)
        self.original = (self.output / legal.SPDX).read_bytes()
        self.original_sidecar = (self.output / (legal.SPDX + ".sha256")).read_bytes()

    def save_manifest(self, document):
        legal.write(self.output / legal.SPDX, document)
        (self.output / (legal.SPDX + ".sha256")).write_text(legal.digest(self.output / legal.SPDX) + "\n")

    def enrich(self):
        return self.sbom_tool.enrich(self.output, [self.cache])

    def test_normal_enrichment_and_final_verification(self):
        report = self.enrich()
        self.assertEqual((self.output / self.sbom_tool.ORIGINAL).read_bytes(), self.original)
        self.assertEqual((self.output / self.sbom_tool.SIDECAR).read_bytes(), self.original_sidecar)
        self.assertEqual((self.output / (legal.SPDX + ".sha256")).read_bytes(),
                         (report["enrichedSpdxSha256"] + "\n").encode("ascii"))
        doc = legal.load(self.output / legal.SPDX)
        self.assertEqual(len(doc["packages"]), 5)
        self.assertEqual(doc["relationships"], json.loads(self.original)["relationships"])
        self.assertEqual(doc["files"], json.loads(self.original)["files"])
        self.assertEqual(doc["documentDescribes"], ["SPDXRef-QueryPact"])
        self.assertTrue(all(p["licenseConcluded"] == "NOASSERTION" for p in doc["packages"]))
        self.assertTrue(all("checksums" not in p for p in doc["packages"]))
        example = next(r for r in doc["packages"] if r["name"] == "Example.Package")
        self.assertEqual(example["licenseDeclared"], "MIT")
        self.assertIn("publisher expression only", example["licenseComments"])
        self.assertEqual(sum(r["added"] for r in report["packages"]), 2)
        reconciled = legal.reconcile(self.output)
        self.assertTrue(reconciled["spdxModified"])
        self.assertTrue(reconciled["coverageAudit"]["spdxModified"])
        self.assertEqual(reconciled["effectiveInputsMissingFromSpdx"], [])
        legal.checksums(self.output)
        legal.verify(self.output)
        with self.assertRaisesRegex(ValueError, "Public release BLOCKED"):
            legal.verify(self.output, public=True)

    def test_enriched_sidecar_rejects_crlf(self):
        report = self.enrich()
        sidecar = self.output / (legal.SPDX + ".sha256")
        expected = (report["enrichedSpdxSha256"] + "\n").encode("ascii")
        self.assertEqual(sidecar.read_bytes(), expected)
        sidecar.write_bytes(expected.replace(b"\n", b"\r\n"))
        with self.assertRaisesRegex(ValueError, "Invalid enriched sidecar"):
            self.sbom_tool.verify(self.output)

    @unittest.skipUnless(POWERSHELL, "PowerShell required for script regression")
    def test_powershell_package_roots_and_missing_exact_archive(self):
        script = Path(__file__).resolve().parent / "test_New-Checksums.ps1"
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(script),
             "-SyntheticOutput", str(self.output)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PowerShell SBOM argument regressions passed", result.stdout)

    @unittest.skipUnless(POWERSHELL, "PowerShell required for script regression")
    def test_checksum_script_verifies_enriched_manifest(self):
        self.enrich()
        before = (self.output / legal.SPDX).read_bytes()
        result = self.fixture.run_checksum_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, (self.output / legal.SPDX).read_bytes())
        self.assertTrue(legal.load(self.output / legal.REPORT)["spdxModified"])
        legal.verify(self.output)

    def test_archive_payload_contradiction(self):
        archive = self.cache / "example.package/1.2.3/example.package.1.2.3.nupkg"
        with zipfile.ZipFile(archive) as z:
            rows = {n: z.read(n) for n in z.namelist()}
        rows["lib/net10.0/Example.dll"] = b"incorrect DLL"
        with zipfile.ZipFile(archive, "w") as z:
            for n, data in rows.items(): z.writestr(n, data)
        evidence = legal.load(self.output / legal.EVIDENCE)
        meta = next(p for p in evidence["packages"] if p["id"] == "Example.Package")
        meta["nupkgSha256"] = legal.digest(archive)
        meta["nupkgSha512"] = base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
        legal.write(self.output / legal.EVIDENCE, evidence)
        self.rehash_original_files()
        with self.assertRaisesRegex(ValueError, "Archive payload contradiction"):
            self.enrich()

    def test_missing_or_divergent_physical_payload(self):
        evidence = legal.load(self.output / legal.EVIDENCE)
        evidence["bundleInputs"].append({"bundlePath": "missing.dll", "sha256": "0" * 64,
                                        "package": "example.package", "version": "1.2.3",
                                        "packagePath": "lib/net10.0/missing.dll"})
        from release_bundle import coverage
        evidence["physicalBundle"] = coverage(self.output / "querypact.exe", evidence)
        legal.write(self.output / legal.EVIDENCE, evidence)
        self.rehash_original_files()
        with self.assertRaisesRegex(ValueError, "Missing effective bundle payload"):
            self.enrich()

    def test_metadata_case_collision(self):
        evidence = legal.load(self.output / legal.EVIDENCE)
        row = dict(next(p for p in evidence["packages"] if p["id"] == "Example.Package"))
        row["id"] = "example.package"
        evidence["packages"].append(row)
        legal.write(self.output / legal.EVIDENCE, evidence)
        self.rehash_original_files()
        with self.assertRaisesRegex(ValueError, "metadata collision"):
            self.enrich()

    def test_stale_extra_manifest_refused(self):
        (self.output / "_manifest/old.spdx.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Stale/unexpected manifest"):
            self.enrich()

    def test_strict_json_and_provenance_inventory(self):
        self.enrich()
        path = self.output / self.sbom_tool.PROVENANCE
        text = path.read_text()
        path.write_text(text.replace('"schema": 1,', '"schema": 1, "schema": 1,'))
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            self.sbom_tool.verify(self.output)
        path.write_text(text)
        (path.parent / "fabricated.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Unexpected enrichment files"):
            self.sbom_tool.verify(self.output)

    def test_deterministic_output_and_rerun_refusal(self):
        copy = self.fixture.root / "copy"
        shutil.copytree(self.output, copy)
        first = self.enrich()
        second = self.sbom_tool.enrich(copy, [self.cache])
        self.assertEqual(first, second)
        self.assertEqual((copy / legal.SPDX).read_bytes(), (self.output / legal.SPDX).read_bytes())
        before = {p.relative_to(self.output).as_posix(): p.read_bytes() for p in self.output.rglob("*") if p.is_file()}
        with self.assertRaisesRegex(ValueError, "rerun"):
            self.enrich()
        self.assertEqual(before, {p.relative_to(self.output).as_posix(): p.read_bytes() for p in self.output.rglob("*") if p.is_file()})

    def test_case_insensitive_identity_collision(self):
        doc = legal.load(self.output / legal.SPDX)
        row = dict(doc["packages"][-1], name="example.package", SPDXID="SPDXRef-extra")
        doc["packages"].append(row)
        self.save_manifest(doc)
        with self.assertRaisesRegex(ValueError, "identity collision"):
            self.enrich()
        self.assertFalse((self.output / self.sbom_tool.DIRECTORY).exists())

    def test_duplicate_spdx_id(self):
        doc = legal.load(self.output / legal.SPDX)
        doc["files"][0]["SPDXID"] = doc["packages"][0]["SPDXID"]
        self.save_manifest(doc)
        with self.assertRaisesRegex(ValueError, "duplicate SPDX ID"):
            self.enrich()

    def test_duplicate_purl(self):
        doc = legal.load(self.output / legal.SPDX)
        doc["packages"][-1]["externalRefs"] *= 2
        self.save_manifest(doc)
        with self.assertRaisesRegex(ValueError, "PURL"):
            self.enrich()

    def test_incorrect_existing_version(self):
        doc = legal.load(self.output / legal.SPDX)
        doc["packages"][-1]["versionInfo"] = "1.2.4"
        doc["packages"][-1].pop("externalRefs")
        self.save_manifest(doc)
        with self.assertRaisesRegex(ValueError, "version contradicts"):
            self.enrich()

    def test_missing_effective_package_metadata(self):
        evidence = legal.load(self.output / legal.EVIDENCE)
        evidence["packages"] = [p for p in evidence["packages"] if p["id"] != "Example.Package"]
        legal.write(self.output / legal.EVIDENCE, evidence)
        # Even an updated generated file hash cannot supply missing metadata.
        self.rehash_original_files()
        with self.assertRaisesRegex(ValueError, "Missing effective package"):
            self.enrich()

    def rehash_original_files(self):
        doc = legal.load(self.output / legal.SPDX)
        for row in doc["files"]:
            data = (self.output / row["fileName"].removeprefix("./")).read_bytes()
            for checksum in row["checksums"]:
                checksum["checksumValue"] = hashlib.new(checksum["algorithm"].lower(), data).hexdigest()
        self.save_manifest(doc)

    def test_executable_change(self):
        with (self.output / "querypact.exe").open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "Executable changed"):
            self.enrich()

    def test_executable_evidence_hash_change(self):
        evidence = legal.load(self.output / legal.EVIDENCE)
        evidence["exeSha256"] = "0" * 64
        legal.write(self.output / legal.EVIDENCE, evidence)
        with self.assertRaisesRegex(ValueError, "Executable changed"):
            self.enrich()

    def test_source_archive_contradiction(self):
        archive = self.cache / "example.package/1.2.3/example.package.1.2.3.nupkg"
        with archive.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "Source archive hash"):
            self.enrich()

    def test_source_endpoint_contradiction(self):
        evidence = legal.load(self.output / legal.EVIDENCE)
        next(p for p in evidence["packages"] if p["id"] == "Example.Package")["source"] = "https://invalid.example/"
        legal.write(self.output / legal.EVIDENCE, evidence)
        self.rehash_original_files()
        with self.assertRaisesRegex(ValueError, "Untrusted NuGet source"):
            self.enrich()

    def test_nuspec_contradiction_even_with_current_original_file_hashes(self):
        evidence = legal.load(self.output / legal.EVIDENCE)
        next(p for p in evidence["packages"] if p["id"] == "Example.Package")["license"]["value"] = "Apache-2.0"
        legal.write(self.output / legal.EVIDENCE, evidence)
        self.rehash_original_files()
        with self.assertRaisesRegex(ValueError, "Nuspec declaration"):
            self.enrich()

    def test_original_assertion_requires_evidence(self):
        doc = legal.load(self.output / legal.SPDX)
        doc["packages"][0]["licenseDeclared"] = "MIT"
        self.save_manifest(doc)
        with self.assertRaisesRegex(ValueError, "Original declaration"):
            self.enrich()

    def test_missing_or_invalid_generator_sidecar(self):
        sidecar = self.output / (legal.SPDX + ".sha256")
        sidecar.unlink()
        with self.assertRaisesRegex(ValueError, "sidecar required"):
            self.enrich()
        sidecar.write_text("0" * 64)
        with self.assertRaisesRegex(ValueError, "sidecar"):
            self.enrich()

    def test_modified_manifest_fields_rejected_with_updated_sidecar(self):
        self.enrich()
        baseline = legal.load(self.output / legal.SPDX)
        import copy
        for mutation in ("declaration", "conclusion", "relationships", "documentDescribes", "file-checksum", "new-package-name", "missing-package"):
            with self.subTest(mutation=mutation):
                doc = copy.deepcopy(baseline)
                if mutation == "declaration": doc["packages"][0]["licenseDeclared"] = "MIT"
                elif mutation == "conclusion": doc["packages"][-1]["licenseConcluded"] = "MIT"
                elif mutation == "relationships": doc["relationships"] = []
                elif mutation == "documentDescribes": doc["documentDescribes"] = ["SPDXRef-example"]
                elif mutation == "file-checksum": doc["files"][0]["checksums"][0]["checksumValue"] = "0" * 64
                elif mutation == "new-package-name": doc["packages"][-1]["name"] = "invented"
                elif mutation == "missing-package": doc["packages"].pop()
                self.save_manifest(doc)
                with self.assertRaisesRegex(ValueError, "Unauthorized SPDX"):
                    self.sbom_tool.verify(self.output)
        self.save_manifest(baseline)

    def test_malformed_or_fabricated_provenance(self):
        self.enrich()
        path = self.output / self.sbom_tool.PROVENANCE
        baseline = legal.load(path)
        import copy
        for mutation in ("operations", "original-hash", "witness-nuspec", "witness-payload", "unknown-field", "blocked-gate"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(baseline)
                if mutation == "operations": report["operations"] = []
                elif mutation == "original-hash": report["originalSpdxSha256"] = "0" * 64
                elif mutation == "witness-nuspec": report["archiveWitnesses"][0]["nuspecBase64"] = base64.b64encode(b"fake").decode()
                elif mutation == "witness-payload": report["archiveWitnesses"][0]["verifiedArchivePayloads"] = []
                elif mutation == "unknown-field": report["legalCleared"] = True
                elif mutation == "blocked-gate": report["publicReleaseGate"] = "APPROVED"
                legal.write(path, report)
                with self.assertRaises(ValueError): self.sbom_tool.verify(self.output)
        legal.write(path, baseline)

    def test_partial_or_removed_provenance(self):
        self.enrich()
        (self.output / self.sbom_tool.PROVENANCE).unlink()
        with self.assertRaisesRegex(ValueError, "Partial enrichment"):
            legal.reconcile(self.output)

    def test_changed_notice_rejected(self):
        self.enrich()
        notice = legal.load(self.output / legal.INVENTORY)["notices"][0]["path"]
        (self.output / notice).write_text("fabricated notice")
        with self.assertRaisesRegex(ValueError, "notice hash"):
            self.sbom_tool.verify(self.output)

    def test_stale_checksums_and_reconciliation_refused(self):
        (self.output / "SHA256SUMS.txt").write_text("old")
        with self.assertRaisesRegex(ValueError, "Stale checksums"):
            self.enrich()
        (self.output / "SHA256SUMS.txt").unlink()
        (self.output / legal.REPORT).write_text("old")
        with self.assertRaisesRegex(ValueError, "Stale checksums"):
            self.enrich()

    def test_report_modification_and_final_checksum_tampering(self):
        self.enrich()
        legal.reconcile(self.output)
        report = legal.load(self.output / legal.REPORT)
        report["spdxModified"] = False
        legal.write(self.output / legal.REPORT, report)
        with self.assertRaisesRegex(ValueError, "Stale reconciliation"):
            legal.checksums(self.output)
        (self.output / legal.REPORT).unlink()
        legal.reconcile(self.output)
        legal.checksums(self.output)
        sums = self.output / "SHA256SUMS.txt"
        sums.write_text(sums.read_text().replace(legal.digest(self.output / self.sbom_tool.PROVENANCE), "0" * 64))
        with self.assertRaisesRegex(ValueError, "Invalid checksum"):
            legal.verify(self.output)


if __name__ == "__main__":
    unittest.main()
