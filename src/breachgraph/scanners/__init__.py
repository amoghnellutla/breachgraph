from breachgraph.scanners.base import ScanContext, Scanner, ScannerOutcome
from breachgraph.scanners.checkov import CheckovScanner
from breachgraph.scanners.cicd import CicdScanner
from breachgraph.scanners.gitleaks import GitleaksScanner
from breachgraph.scanners.sarif_import import SarifImporter
from breachgraph.scanners.semgrep import SemgrepScanner
from breachgraph.scanners.trivy import TrivyScanner
from breachgraph.scanners.zap import ZapScanner
from breachgraph.scanners.zizmor import ZizmorScanner

SCANNERS: dict[str, Scanner] = {
    s.name: s
    for s in (
        SemgrepScanner(),
        GitleaksScanner(),
        TrivyScanner(),
        CheckovScanner(),
        ZizmorScanner(),
        CicdScanner(),
        ZapScanner(),
    )
}
# The built-in checks have no report of their own to import.
IMPORTERS: dict[str, Scanner] = {
    **{k: v for k, v in SCANNERS.items() if k != "cicd"},
    "sarif": SarifImporter(),
}

__all__ = ["IMPORTERS", "SCANNERS", "ScanContext", "Scanner", "ScannerOutcome"]
