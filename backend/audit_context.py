"""Authenticated request identity, propagated into async workers."""
from contextvars import ContextVar

actor = ContextVar("netra_actor", default="system")


def current_actor():
    return actor.get()
