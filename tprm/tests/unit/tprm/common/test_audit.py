"""Unit tests for common/audit.py — hash-chain integrity."""

from __future__ import annotations

import asyncio

import pytest

from tprm.common.audit import AuditLog, reset_audit_log


class TestAuditLog:
    def setup_method(self) -> None:
        reset_audit_log()

    async def test_append_single(self) -> None:
        log = AuditLog()
        event = await log.append("pii", "doc-1", "system", "detect", {"EMAIL": 2})
        assert event.stage == "pii"
        assert event.doc_id == "doc-1"
        assert event.hash != ""
        assert len(event.hash) == 64

    async def test_chain_integrity_passes(self) -> None:
        log = AuditLog()
        await log.append("ingestion", "doc-1", "system", "parse")
        await log.append("pii", "doc-1", "system", "detect", {"EMAIL": 3})
        await log.append("gate", "doc-1", "system", "pass")
        assert log.verify_chain() is True

    async def test_chain_integrity_detects_tamper(self) -> None:
        log = AuditLog()
        await log.append("ingestion", "doc-1", "system", "parse")
        await log.append("pii", "doc-1", "system", "detect", {"EMAIL": 3})

        # Tamper with the first event's counts (simulates DB row modification)
        log._events[0].counts = {"EMAIL": 999}
        assert log.verify_chain() is False

    async def test_prev_hash_links(self) -> None:
        log = AuditLog()
        e1 = await log.append("ingestion", "d1", "system", "parse")
        e2 = await log.append("pii", "d1", "system", "detect")
        assert e2.prev_hash == e1.hash

    async def test_genesis_hash_for_first_event(self) -> None:
        log = AuditLog()
        e = await log.append("ingestion", "d1", "system", "parse")
        assert e.prev_hash == "0" * 64

    async def test_events_for_doc_filters(self) -> None:
        log = AuditLog()
        await log.append("ingestion", "doc-1", "system", "parse")
        await log.append("ingestion", "doc-2", "system", "parse")
        await log.append("pii", "doc-1", "system", "detect")
        events = log.events_for_doc("doc-1")
        assert len(events) == 2
        assert all(e.doc_id == "doc-1" for e in events)

    async def test_counts_never_contain_content(self) -> None:
        """Counts dict should contain entity type names + numbers, not PII values."""
        log = AuditLog()
        # A proper audit call passes counts like {"EMAIL": 2} not {"EMAIL": "user@corp.com"}
        event = await log.append("pii", "d1", "system", "detect", {"EMAIL": 2, "PHONE": 1})
        for v in event.counts.values():
            assert isinstance(v, int), "Counts must be integers (counts, not values)"

    async def test_verify_empty_chain(self) -> None:
        log = AuditLog()
        assert log.verify_chain() is True


class TestAuditLogConcurrency:
    async def test_concurrent_appends_chain_valid(self) -> None:
        log = AuditLog()
        tasks = [
            log.append(f"stage-{i}", "doc-1", "system", f"action-{i}")
            for i in range(10)
        ]
        await asyncio.gather(*tasks)
        assert log.verify_chain() is True
        assert len(log.all_events()) == 10
