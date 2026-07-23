"""Scanner adapters."""

from .base import ScannerExecution
from .checkov import CheckovScanner
from .trivy import TrivyScanner

__all__ = ["CheckovScanner", "ScannerExecution", "TrivyScanner"]
