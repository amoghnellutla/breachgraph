from triagegate.scanners.base import ScanContext, Scanner, ScannerOutcome
from triagegate.scanners.checkov import CheckovScanner
from triagegate.scanners.gitleaks import GitleaksScanner
from triagegate.scanners.sarif_import import SarifImporter
from triagegate.scanners.semgrep import SemgrepScanner
from triagegate.scanners.trivy import TrivyScanner
from triagegate.scanners.zap import ZapScanner

SCANNERS: dict[str, Scanner] = {
    s.name: s
    for s in (SemgrepScanner(), GitleaksScanner(), TrivyScanner(), CheckovScanner(), ZapScanner())
}
IMPORTERS: dict[str, Scanner] = {**SCANNERS, "sarif": SarifImporter()}

__all__ = ["IMPORTERS", "SCANNERS", "ScanContext", "Scanner", "ScannerOutcome"]
