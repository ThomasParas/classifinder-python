"""ClassiFinder Python SDK — scan and redact secrets from text."""

from ._client import ClassiFinder
from ._async_client import AsyncClassiFinder
from ._exceptions import (
    ClassiFinderError,
    AuthenticationError,
    RateLimitError,
    InvalidRequestError,
    ForbiddenError,
    ServerError,
    APIConnectionError,
    SecretsDetectedError,
)
from ._models import (
    ScanResult,
    RedactResult,
    TypesResult,
    HealthResult,
    FeedbackResult,
    Finding,
    RedactFinding,
    Span,
    SeveritySummary,
    TypeInfo,
)

__all__ = [
    "ClassiFinder",
    "AsyncClassiFinder",
    "ClassiFinderError",
    "AuthenticationError",
    "RateLimitError",
    "InvalidRequestError",
    "ForbiddenError",
    "ServerError",
    "APIConnectionError",
    "SecretsDetectedError",
    "ScanResult",
    "RedactResult",
    "TypesResult",
    "HealthResult",
    "FeedbackResult",
    "Finding",
    "RedactFinding",
    "Span",
    "SeveritySummary",
    "TypeInfo",
]
