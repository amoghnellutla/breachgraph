"""Trivy: dependency CVEs (SCA), IaC/Dockerfile misconfigurations, licenses, container images,
plus a CycloneDX SBOM artifact."""

from __future__ import annotations

import dataclasses
import re
from typing import Any, ClassVar, cast

from breachgraph.config import TrivyConfig
from breachgraph.models import (
    Category,
    Confidence,
    Finding,
    Location,
    Package,
    Severity,
    ToolStatus,
)
from breachgraph.scanners._util import read_snippet, simple_dir_excludes
from breachgraph.scanners.base import ScanContext, Scanner, ScannerOutcome, Step, as_list

# Registry throttling seen in CI, e.g. "remote Maven repository returned 429 Too Many Requests".
_REGISTRY_ERROR = re.compile(r"429|Too Many Requests|remote Maven repository", re.IGNORECASE)


class TrivyScanner(Scanner):
    name: ClassVar[str] = "trivy"
    binary: ClassVar[str] = "trivy"

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        settings = cast(TrivyConfig, self.settings(ctx.config))
        common = ["--quiet", "--timeout", f"{settings.timeout or ctx.config.timeout}s"]
        if settings.ignore_unfixed:
            common.append("--ignore-unfixed")
        if settings.offline_scan:
            common.append("--offline-scan")
        skip: list[str] = []
        for name in simple_dir_excludes(ctx.config.exclude_paths):
            skip += ["--skip-dirs", name if "/" in name else f"**/{name}"]

        steps: list[Step] = []
        out = ctx.work_dir / "trivy-fs.json"
        steps.append(
            Step(
                [
                    exe,
                    "fs",
                    "--scanners",
                    ",".join(settings.scanners),
                    "--format",
                    "json",
                    "--list-all-pkgs",
                    "--output",
                    str(out),
                    *common,
                    *skip,
                    *settings.extra_args,
                    ".",
                ],
                out,
            )
        )
        if settings.sbom:
            sbom = ctx.work_dir / "sbom.cdx.json"
            steps.append(
                Step(
                    [
                        exe,
                        "fs",
                        "--format",
                        "cyclonedx",
                        "--output",
                        str(sbom),
                        *common,
                        *skip,
                        ".",
                    ],
                    sbom,
                    parse=False,
                )
            )
            ctx.artifacts["sbom"] = str(sbom)
        for i, image in enumerate(settings.images):
            img_out = ctx.work_dir / f"trivy-image-{i}.json"
            steps.append(
                Step(
                    [
                        exe,
                        "image",
                        "--scanners",
                        "vuln",
                        "--format",
                        "json",
                        "--output",
                        str(img_out),
                        *common,
                        *settings.extra_args,
                        image,
                    ],
                    img_out,
                )
            )
        return steps

    def run(self, ctx: ScanContext) -> ScannerOutcome:
        outcome = super().run(ctx)
        settings = cast(TrivyConfig, self.settings(ctx.config))
        if (
            outcome.run.status is ToolStatus.FAILED
            and not settings.offline_scan
            and _REGISTRY_ERROR.search(outcome.run.message or "")
        ):
            # A rate-limited registry should not cost us every dependency finding: retry without
            # registry lookups (declared dependencies are still scanned, transitive Java ones not).
            config = ctx.config.model_copy(deep=True)
            config.scanners.trivy.offline_scan = True
            retry = super().run(dataclasses.replace(ctx, config=config))
            if retry.run.status is ToolStatus.OK:
                retry.run.message = (
                    "package registry unavailable (rate limited); retried with --offline-scan, "
                    "transitive Java dependencies were not resolved"
                )
                retry.run.duration_s = round(retry.run.duration_s + outcome.run.duration_s, 2)
                return retry
        return outcome

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        image = raw.get("ArtifactName") if raw.get("ArtifactType") == "container_image" else None
        findings: list[Finding] = []
        for result in raw.get("Results") or []:
            target = str(result.get("Target", ""))
            cls = result.get("Class", "")
            lines = {
                p.get("ID"): (p.get("Locations") or [{}])[0].get("StartLine")
                for p in result.get("Packages") or []
                if p.get("ID")
            }
            for v in result.get("Vulnerabilities") or []:
                findings.append(self._vuln(v, target, cls, image, lines, result.get("Type")))
            for m in result.get("Misconfigurations") or []:
                if m.get("Status", "FAIL") == "FAIL":
                    findings.append(self._misconfig(m, target, ctx))
            for lic in result.get("Licenses") or []:
                findings.append(self._license(lic, target))
        return findings

    def _vuln(
        self,
        v: dict[str, Any],
        target: str,
        cls: str,
        image: str | None,
        lines: dict[str, int | None],
        ecosystem: str | None,
    ) -> Finding:
        vid = v["VulnerabilityID"]
        pkg, installed, fixed = (
            v.get("PkgName", "?"),
            v.get("InstalledVersion"),
            v.get("FixedVersion"),
        )
        scores = [
            s.get("V3Score") or s.get("V40Score")
            for s in (v.get("CVSS") or {}).values()
            if isinstance(s, dict)
        ]
        cvss = max((float(s) for s in scores if s), default=None)
        title = f"{vid} in {pkg} {installed or ''}".strip()
        if v.get("Title"):
            title += f": {v['Title']}"
        if fixed:
            remediation = f"Upgrade {pkg} from {installed} to {fixed.split(',')[0].strip()} or later."
        else:
            status = v.get("Status") or "no fix available"
            remediation = (
                f"No fixed version of {pkg} yet ({status}). Check whether the vulnerable code "
                "path is reachable, apply vendor mitigations, or replace the package."
            )
        container = image is not None or cls == "os-pkgs"
        path = image if image else target
        return Finding(
            tool=self.name,
            rule_id=vid,
            title=title[:200],
            description=(v.get("Description") or "").strip(),
            severity=Severity.parse(v.get("Severity")),
            category=Category.CONTAINER if container else Category.SCA,
            confidence=Confidence.HIGH,
            location=Location(
                path=path,
                start_line=None if image else lines.get(str(v.get("PkgID"))),
                in_repo=image is None,
            ),
            cwe=[str(c) for c in as_list(v.get("CweIDs"))],
            vuln_ids=[vid, *[str(x) for x in as_list(v.get("VendorIDs"))]],
            cvss=cvss,
            package=Package(name=pkg, version=installed, fixed_version=fixed, ecosystem=ecosystem),
            remediation=remediation,
            references=[u for u in [v.get("PrimaryURL"), *as_list(v.get("References"))[:5]] if u],
        )

    def _misconfig(self, m: dict[str, Any], target: str, ctx: ScanContext) -> Finding:
        cause = m.get("CauseMetadata") or {}
        start, end = cause.get("StartLine") or None, cause.get("EndLine") or None
        code = [ln.get("Content", "") for ln in (cause.get("Code") or {}).get("Lines") or []]
        snippet = "\n".join(code) if code else read_snippet(ctx.target, target, start, end)
        message = m.get("Message") or ""
        description = f"{message}\n\n{m.get('Description', '')}".strip()
        return Finding(
            tool=self.name,
            rule_id=m.get("AVDID") or m.get("ID", "misconfig"),
            title=m.get("Title") or m.get("ID", "Misconfiguration"),
            description=description,
            severity=Severity.parse(m.get("Severity")),
            category=Category.IAC,
            confidence=Confidence.HIGH,
            location=Location(path=target, start_line=start, end_line=end, snippet=snippet),
            remediation=m.get("Resolution"),
            references=[u for u in [m.get("PrimaryURL"), *as_list(m.get("References"))[:3]] if u],
        )

    def _license(self, lic: dict[str, Any], target: str) -> Finding:
        name = lic.get("Name", "unknown")
        pkg = lic.get("PkgName") or lic.get("FilePath") or target
        return Finding(
            tool=self.name,
            rule_id=f"license:{name}",
            title=f"{lic.get('Category', 'restricted').title()} license {name} in {pkg}",
            description=(
                f"Package {pkg} is licensed under {name}, which Trivy classifies as "
                f"'{lic.get('Category', 'unknown')}'. Check it against your license policy."
            ),
            severity=Severity.parse(lic.get("Severity")),
            category=Category.SCA,
            confidence=Confidence.MEDIUM,
            location=Location(path=lic.get("FilePath") or target),
            package=Package(name=str(pkg)),
            references=[lic["Link"]] if lic.get("Link") else [],
        )
