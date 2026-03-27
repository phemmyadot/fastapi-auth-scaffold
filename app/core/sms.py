from twilio.rest import Client

from app.core.config import settings

_client: Client | None = None


def _get_client() -> Client:
    global _client
    if _client is None:
        _client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    return _client


def send_sms(to: str, body: str) -> None:
    """Send an SMS via Twilio."""
    client = _get_client()
    client.messages.create(
        body=body,
        from_=settings.TWILIO_FROM_NUMBER,
        to=to,
    )
