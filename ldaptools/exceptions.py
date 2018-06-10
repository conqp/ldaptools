"""Common exceptions."""

__all__ = ['InvalidName', 'IdentifiersExhausted']


class InvalidName(ValueError):
    """Indicates that an invalid name has been specified."""

    def __init__(self, name):
        """Sets the invalid name."""
        super().__init__(name)
        self.name = name

    def __str__(self):
        """Returns the error message."""
        return 'Invalid name: "{}".'.format(self.name)


class IdentifiersExhausted(Exception):
    """Indicates that the respective pool of identifiers is exhausted."""

    pass
