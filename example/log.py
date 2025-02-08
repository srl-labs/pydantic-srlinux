import logging

from rich.logging import RichHandler
from rich.traceback import install


def setup_logging() -> logging.Logger:
    """Setup logging"""

    # Replace the basic logging config with Rich handler
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, markup=False)],
    )

    logging.getLogger("httpx").setLevel(logging.INFO)

    install(show_locals=True)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    return logging.getLogger(__name__)
