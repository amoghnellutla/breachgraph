from breachgraph.scanners.base import ScanContext, Scanner, ScannerOutcome
from breachgraph.scanners.checkov import CheckovScanner
from breachgraph.scanners.gitleaks import GitleaksScanner
from breachgraph.scanners.sarif_import import SarifImporter
from breachgraph.scanners.semgrep import SemgrepScanner
from breachgraph.scanners.trivy import TrivyScanner
from breachgraph.scanners.zap import ZapScanner

SCANNERS: dict[str, Scanner] = {
    s.name: s
    for s in (SemgrepScanner(), GitleaksScanner(), TrivyScanner(), CheckovScanner(), ZapScanner())
}
IMPORTERS: dict[str, Scanner] = {**SCANNERS, "sarif": SarifImporter()}

__all__ = ["IMPORTERS", "SCANNERS", "ScanContext", "Scanner", "ScannerOutcome"]
