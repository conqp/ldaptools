"""LDIF file models."""

from functools import wraps
from os import linesep
from typing import NamedTuple

from ldaptools.config import CONFIG


__all__ = ['DistinguishedName', 'DNComponent', 'LDIF', 'LDIFEntry']


class DistinguishedName(list):
    """Represents a distinguished name."""

    def __str__(self):
        """Returns a string representation of the distinguished name."""
        return ','.join(str(component) for component in self)

    @classmethod
    def create(cls, ou, *dc):
        """Creates a new distinguished name."""
        return cls((ou, *dc))

    @classmethod
    def user(cls, uid, *dc, ou=CONFIG['user']['ou']):
        """Creates a distinguished name for a user."""
        uid = DNComponent('uid', uid)
        return cls((uid, ou, *dc))

    @classmethod
    def group(cls, cn, *dc, ou=CONFIG['group']['ou']):
        """Creates a distinguished name for a group."""
        cn = DNComponent('cn', cn)
        return cls((cn, ou, *dc))


class DNComponent(NamedTuple):
    """A component of a distinguished name."""

    key: str
    value: str

    def __str__(self):
        return f'{self.key}={self.value}'


class LDIF(list):
    """An LDIF file, containing key-value pairs."""

    def __str__(self):
        return linesep.join(str(entry) for entry in self)

    @classmethod
    def constructor(cls, function):
        """Decorator to create an LDIF instance
        from the return values of a function.
        """
        @wraps(function)
        def wrapper(*args, **kwargs):
            """Wraps the original function."""
            return cls(function(*args, **kwargs))

        return wrapper


class LDIFEntry(NamedTuple):
    """An LDIF file's entry."""

    key: str
    value: str

    def __str__(self):
        return f'{self.key}: {self.value}'
