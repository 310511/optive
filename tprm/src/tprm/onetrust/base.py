"""OneTrust client abstract interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class OneTrustClient(ABC):
    """Abstract interface for OneTrust TPRM integration."""

    @abstractmethod
    async def upsert_vendor(self, vendor_id: str, meta: dict[str, Any]) -> str:
        """Create or update a vendor record. Returns OneTrust vendor ID."""

    @abstractmethod
    async def create_assessment(self, vendor_ot_id: str, meta: dict[str, Any]) -> str:
        """Create an assessment. Returns OneTrust assessment ID."""

    @abstractmethod
    async def push_findings(self, assessment_ot_id: str, findings: list[dict[str, Any]]) -> None:
        """Push sanitized findings to OneTrust."""

    @abstractmethod
    async def update_status(self, assessment_ot_id: str, status: str) -> None:
        """Update assessment status in OneTrust."""
