# Structured logging for MEYVIZHI backend.
# Never log API keys, passwords, JWTs or full user message content.
import logging
import sys

_configured = False


def configure_logging() -> None:
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").handlers = [handler]
    _configured = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)


def log_event(logger: logging.Logger, event: str, **fields) -> None:
    """Log a structured event as key=value pairs (secrets must never be passed in)."""
    parts = [event]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    logger.info(" ".join(parts))
