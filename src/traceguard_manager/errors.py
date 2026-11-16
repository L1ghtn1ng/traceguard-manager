"""Errors whose messages are written for the person using the dashboard."""


class DomainError(ValueError):
    """A validation failure with a message that is safe to show to the user."""
