from secgate.scanners.base import ScanContext, Scanner, ScannerOutcome
from secgate.scanners.checkov import CheckovScanner
from secgate.scanners.gitleaks import GitleaksScanner
from secgate.scanners.sarif_import import SarifImporter
from secgate.scanners.semgrep import SemgrepScanner
from secgate.scanners.trivy import TrivyScanner
from secgate.scanners.zap import ZapScanner

SCANNERS: dict[str, Scanner] = {
    s.name: s
    for s in (SemgrepScanner(), GitleaksScanner(), TrivyScanner(), CheckovScanner(), ZapScanner())
}
IMPORTERS: dict[str, Scanner] = {**SCANNERS, "sarif": SarifImporter()}

__all__ = ["IMPORTERS", "SCANNERS", "ScanContext", "Scanner", "ScannerOutcome"]
