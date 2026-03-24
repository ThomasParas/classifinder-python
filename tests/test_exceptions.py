"""Tests for the exception hierarchy."""

from classifinder._exceptions import (
    ClassiFinderError,
    AuthenticationError,
    RateLimitError,
    InvalidRequestError,
    ForbiddenError,
    ServerError,
    APIConnectionError,
    SecretsDetectedError,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_base(self):
        for exc_class in (
            AuthenticationError,
            RateLimitError,
            InvalidRequestError,
            ForbiddenError,
            ServerError,
            APIConnectionError,
        ):
            assert issubclass(exc_class, ClassiFinderError)

    def test_base_has_message_and_status(self):
        e = ClassiFinderError("something broke", status_code=500)
        assert e.message == "something broke"
        assert e.status_code == 500
        assert str(e) == "something broke"

    def test_authentication_error(self):
        e = AuthenticationError("bad key")
        assert e.status_code == 401
        assert e.message == "bad key"

    def test_rate_limit_error(self):
        e = RateLimitError("too fast", retry_after=30)
        assert e.status_code == 429
        assert e.retry_after == 30

    def test_invalid_request_error(self):
        e = InvalidRequestError("too big", code="payload_too_large")
        assert e.status_code == 400
        assert e.code == "payload_too_large"

    def test_forbidden_error(self):
        e = ForbiddenError("upgrade needed", code="tier_limit_exceeded")
        assert e.status_code == 403
        assert e.code == "tier_limit_exceeded"

    def test_server_error(self):
        e = ServerError("internal error")
        assert e.status_code == 500

    def test_api_connection_error(self):
        e = APIConnectionError("timeout")
        assert e.status_code is None
        assert e.message == "timeout"

    def test_secrets_detected_error(self):
        e = SecretsDetectedError(
            "Found 2 secrets", findings_count=2, findings=["f1", "f2"], summary={"critical": 1}
        )
        assert isinstance(e, ClassiFinderError)
        assert e.findings_count == 2
        assert e.findings == ["f1", "f2"]
        assert e.summary == {"critical": 1}
        assert e.status_code is None
