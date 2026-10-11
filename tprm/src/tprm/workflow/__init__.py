"""TPRM Workflow stage — public interfaces."""

from tprm.workflow.approval import approve
from tprm.workflow.state_machine import WorkflowStateMachine

__all__ = ["WorkflowStateMachine", "approve"]
