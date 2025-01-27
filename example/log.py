import logging

from rich.logging import RichHandler
from rich.traceback import install


def setup_logging():
    """Setup logging"""

    # Replace the basic logging config with Rich handler
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)],
    )

    logging.getLogger("httpx").setLevel(logging.INFO)

    install(show_locals=True)
