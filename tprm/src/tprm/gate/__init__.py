"""Security Gate — public interfaces: process() and verify_gate_approved()."""

from tprm.gate.gate import process
from tprm.gate.verifier import verify_gate_approved

__all__ = ["process", "verify_gate_approved"]
