"""Common exceptions."""

__all__ = ['InvalidName', 'IdentifiersExhausted']


class InvalidName(ValueError):
    """Indicates that an invalid name has been specified."""

    def __init__(self, name: str):
        """Sets the invalid name."""
        super().__init__(name)
        self.name = name


class IdentifiersExhausted(Exception):
    """Indicates that the respective pool of identifiers is exhausted."""
