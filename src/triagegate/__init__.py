"""triagegate: one security gate for CI pipelines."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("triagegate")
except PackageNotFoundError:  # running from a source checkout
    __version__ = "0.0.0+dev"

PROJECT_URL = "https://github.com/OWNER/triagegate"
