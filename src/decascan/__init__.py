"""decascan — a scanner for the OWASP MCP, LLM Applications and web Top 10 lists."""

__version__ = "0.1.0"

import logging as _logging

_logging.getLogger("decascan").addHandler(_logging.NullHandler())

__all__ = ["__version__"]
