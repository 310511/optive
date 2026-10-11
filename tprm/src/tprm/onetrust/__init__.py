"""OneTrust TPRM adapter — public interfaces."""

from tprm.onetrust.base import OneTrustClient
from tprm.onetrust.mock import MockOneTrustClient

__all__ = ["OneTrustClient", "MockOneTrustClient"]
