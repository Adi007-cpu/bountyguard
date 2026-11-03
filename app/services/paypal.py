from decimal import Decimal
import logging
import os
from typing import Any, Optional
import httpx
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class PayPalConfigurationError(Exception):
    """Raised when required PayPal credentials or configurations are missing."""
    pass


class PayPalAuthError(Exception):
    """Raised when authentication with PayPal API fails or returns an invalid token."""
    pass


class PayPalPayoutError(Exception):
    """Raised when creating or processing a PayPal payout fails."""
    pass


class PayPalWebhookVerificationError(Exception):
    """Raised when webhook signature verification fails."""
    pass


class PayPalSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    paypal_client_id: Optional[str] = None
    paypal_client_secret: Optional[str] = None
    paypal_webhook_id: Optional[str] = None
    paypal_api_base: str = "https://api-m.sandbox.paypal.com"
    request_timeout_seconds: float = 15.0


class PayPalService:
    def __init__(self, settings: Optional[Any] = None):
        if settings is None:
            try:
                from app.config import get_settings
                self.settings = get_settings()
            except Exception:
                self.settings = PayPalSettings()
        else:
            self.settings = settings
        self.client_id = self.settings.paypal_client_id
        self.client_secret = self.settings.paypal_client_secret
        self.webhook_id = self.settings.paypal_webhook_id
        self.base_url = self.settings.paypal_api_base.rstrip("/")
        self.timeout = httpx.Timeout(self.settings.request_timeout_seconds, connect=5.0)

    def _validate_credentials(self):
        """Fail fast if PayPal credentials are missing or unconfigured."""
        if not self.client_id or self.client_id.strip() in ("", "your_paypal_client_id", "mock_client_id"):
            raise PayPalConfigurationError(
                "PAYPAL_CLIENT_ID is not configured. Please supply valid PayPal API credentials."
            )
        if not self.client_secret or self.client_secret.strip() in ("", "your_paypal_client_secret", "mock_client_secret"):
            raise PayPalConfigurationError(
                "PAYPAL_CLIENT_SECRET is not configured. Please supply valid PayPal API credentials."
            )

    async def get_access_token(self) -> str:
        self._validate_credentials()

        async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout) as client:
            try:
                resp = await client.post(
                    "/v1/oauth2/token",
                    data={"grant_type": "client_credentials"},
                    auth=(self.client_id, self.client_secret),
                    headers={"Accept": "application/json", "Accept-Language": "en_US"},
                )
            except httpx.RequestError as exc:
                raise PayPalAuthError(f"Network error connecting to PayPal OAuth: {exc}") from exc

            if resp.status_code != 200:
                raise PayPalAuthError(
                    f"PayPal authentication failed [HTTP {resp.status_code}]: {resp.text}"
                )

            data = resp.json()
            token = data.get("access_token")
            if not token or not isinstance(token, str) or not token.strip():
                raise PayPalAuthError("PayPal OAuth response did not contain a valid access_token.")

            return token

    async def create_payout(
        self,
        sender_batch_id: str,
        recipient_email: str,
        amount: Decimal,
        currency: str = "USD",
        note: str = "Bounty payout from BountyGuard",
    ) -> dict[str, Any]:
        """Creates a PayPal batch payout using a persisted, UUID-based sender_batch_id for idempotency.
        PayPal guarantees idempotency for requests sharing the same sender_batch_id within 30 days.
        """
        if not sender_batch_id or not sender_batch_id.strip():
            raise PayPalPayoutError("sender_batch_id is required for idempotency protection.")

        if amount <= Decimal("0.00"):
            raise PayPalPayoutError(f"Invalid payout amount: ${amount:.2f}")

        token = await self.get_access_token()

        payload = {
            "sender_batch_header": {
                "sender_batch_id": sender_batch_id,
                "email_subject": "You have received a bounty payout!",
                "email_message": note,
            },
            "items": [
                {
                    "recipient_type": "EMAIL",
                    "amount": {"value": f"{amount:.2f}", "currency": currency},
                    "note": note,
                    "sender_item_id": f"item_{sender_batch_id}",
                    "receiver": recipient_email,
                }
            ],
        }

        async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout) as client:
            try:
                resp = await client.post(
                    "/v1/payments/payouts",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
            except httpx.RequestError as exc:
                raise PayPalPayoutError(f"Network error sending payout to PayPal: {exc}") from exc

            if resp.status_code not in (200, 201):
                raise PayPalPayoutError(
                    f"PayPal payout request failed [HTTP {resp.status_code}]: {resp.text}"
                )

            return resp.json()

    async def get_payout_batch(self, payout_batch_id: str) -> dict[str, Any]:
        """Queries PayPal Payouts API for the current status of a payout batch."""
        if not payout_batch_id or not payout_batch_id.strip():
            raise PayPalPayoutError("payout_batch_id is required to query payout status.")

        token = await self.get_access_token()

        async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    f"/v1/payments/payouts/{payout_batch_id}",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
            except httpx.RequestError as exc:
                raise PayPalPayoutError(f"Network error fetching payout batch status: {exc}") from exc

            if resp.status_code != 200:
                raise PayPalPayoutError(
                    f"PayPal payout query failed [HTTP {resp.status_code}]: {resp.text}"
                )

            return resp.json()

    async def verify_webhook_signature(
        self,
        headers: dict[str, str],
        body_json: dict[str, Any],
    ) -> bool:
        """Verifies incoming PayPal webhook signature via PayPal's verify-webhook-signature API.
        Fails closed if PAYPAL_WEBHOOK_ID is unconfigured.
        """
        if not self.webhook_id or not self.webhook_id.strip():
            logger.error("PAYPAL_WEBHOOK_ID is not configured. Rejecting webhook (fail closed).")
            raise PayPalWebhookVerificationError(
                "PAYPAL_WEBHOOK_ID is not configured on this server. Webhook verification rejected."
            )

        token = await self.get_access_token()

        verify_payload = {
            "auth_algo": headers.get("paypal-auth-algo") or headers.get("PAYPAL-AUTH-ALGO"),
            "cert_url": headers.get("paypal-cert-url") or headers.get("PAYPAL-CERT-URL"),
            "transmission_id": headers.get("paypal-transmission-id") or headers.get("PAYPAL-TRANSMISSION-ID"),
            "transmission_sig": headers.get("paypal-transmission-sig") or headers.get("PAYPAL-TRANSMISSION-SIG"),
            "transmission_time": headers.get("paypal-transmission-time") or headers.get("PAYPAL-TRANSMISSION-TIME"),
            "webhook_id": self.webhook_id,
            "webhook_event": body_json,
        }

        async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout) as client:
            try:
                resp = await client.post(
                    "/v1/notifications/verify-webhook-signature",
                    json=verify_payload,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
                if resp.status_code == 200:
                    status_str = resp.json().get("verification_status", "")
                    return status_str.upper() == "SUCCESS"
            except Exception as e:
                logger.error(f"Error calling PayPal webhook verification API: {e}")
                return False

        return False
