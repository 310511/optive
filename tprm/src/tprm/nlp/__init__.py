"""Local NLP stage — public interfaces."""

from tprm.nlp.classifier import classify_doc, classify_section
from tprm.nlp.context import build_context
from tprm.nlp.relations import build_relations

__all__ = ["build_context", "build_relations", "classify_doc", "classify_section"]
