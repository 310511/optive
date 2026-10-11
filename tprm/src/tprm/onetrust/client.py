"""HttpOneTrustClient — opt-in HTTP adapter with OAuth2 and retry."""

from __future__ import annotations

from typing import Any

from tprm.common.errors import OneTrustError
from tprm.common.logging import get_logger
from tprm.onetrust.base import OneTrustClient
from tprm.onetrust.mock import _validate_payload

log = get_logger(__name__)


class HttpOneTrustClient(OneTrustClient):
    """HTTP OneTrust client with OAuth2 client-credentials, retry, rate limiting.

    Requires TPRM_ONETRUST_ADAPTER=http and valid OAuth2 credentials.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        max_retries: int = 3,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._max_retries = max_retries
        self._token: str | None = None

    async def _get_token(self) -> str:
        """Fetch or return cached OAuth2 bearer token."""
        if self._token:
            return self._token
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self._base_url}/oauth/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    },
                )
                resp.raise_for_status()
                self._token = resp.json()["access_token"]
                return self._token
        except Exception as exc:
            raise OneTrustError(f"OAuth2 token fetch failed: {exc}") from exc

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Execute HTTP request with exponential backoff retry."""
        import asyncio
        import httpx

        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}", "X-Idempotency-Key": kwargs.pop("idempotency_key", "")}

        for attempt in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.request(method, f"{self._base_url}{path}", headers=headers, **kwargs)
                    if resp.status_code == 429:
                        wait = 2 ** attempt
                        await asyncio.sleep(wait)
                        continue
                    if resp.status_code >= 400:
                        raise OneTrustError(f"OneTrust API error {resp.status_code}: {resp.text[:200]}")
                    return resp.json() if resp.content else {}
            except OneTrustError:
                raise
            except Exception as exc:
                if attempt >= self._max_retries:
                    raise OneTrustError(f"OneTrust request failed after {self._max_retries} retries: {exc}") from exc
                await asyncio.sleep(2 ** attempt)
        return {}

    async def upsert_vendor(self, vendor_id: str, meta: dict[str, Any]) -> str:
        result = await self._request("POST", "/api/vendors", json={"externalId": vendor_id, **meta})
        return result.get("id", vendor_id)

    async def create_assessment(self, vendor_ot_id: str, meta: dict[str, Any]) -> str:
        result = await self._request("POST", f"/api/vendors/{vendor_ot_id}/assessments", json=meta)
        return result.get("id", "")

    async def push_findings(self, assessment_ot_id: str, findings: list[dict[str, Any]]) -> None:
        _validate_payload(findings)
        await self._request(
            "POST",
            f"/api/assessments/{assessment_ot_id}/findings",
            json={"findings": findings},
        )

    async def update_status(self, assessment_ot_id: str, status: str) -> None:
        await self._request(
            "PATCH",
            f"/api/assessments/{assessment_ot_id}",
            json={"status": status},
        )
