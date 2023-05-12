"""LDIF file models."""

from __future__ import annotations
from functools import partial, wraps
from os import linesep
from typing import Any, Callable, Iterator, NamedTuple, Optional

from ldaptools.config import CONFIG


__all__ = ['DistinguishedName', 'DNComponent', 'LDIFEntry', 'LDIF']


def domain_components(domain: str) -> Iterator[DNComponent]:
    """Yields domain components."""

    return map(partial(DNComponent, 'dc'), filter(None, domain.split('.')))


class DistinguishedName(list):
    """Represents a distinguished name."""

    def __str__(self):
        """Returns a string representation of the distinguished name."""
        return ','.join(str(component) for component in self)

    @classmethod
    def for_user(
            cls,
            uid: str,
            domain: str,
            *,
            ou: Optional[str] = None
    ) -> DistinguishedName:
        """Creates a distinguished name for a user."""
        return cls([
            DNComponent('uid', uid),
            DNComponent('ou', CONFIG.get('user', 'ou') if ou is None else ou),
            *domain_components(domain)
        ])

    @classmethod
    def for_group(
            cls,
            cn: str,
            domain: str,
            *,
            ou: Optional[str] = None
    ) -> DistinguishedName:
        """Creates a distinguished name for a group."""
        return cls([
            DNComponent('cn', cn),
            DNComponent('ou', CONFIG.get('group', 'ou') if ou is None else ou),
            *domain_components(domain)
        ])

    @classmethod
    def for_master(
            cls,
            domain: str,
            *,
            cn: Optional[str] = None
    ) -> DistinguishedName:
        """Creates a distinguished name for administrative operations."""
        return cls([
            DNComponent(
                'cn',
                CONFIG.get('common', 'master') if cn is None else cn
            ),
            *domain_components(domain)
        ])


class DNComponent(NamedTuple):
    """A component of a distinguished name."""

    key: str
    value: str

    def __str__(self):
        return f'{self.key}={self.value}'


class LDIFEntry(NamedTuple):
    """An LDIF file's entry."""

    key: str
    value: Any

    def __str__(self):
        return f'{self.key}: {self.value}'


class LDIF(list):
    """An LDIF file, containing key-value pairs."""

    def __str__(self):
        return linesep.join(str(entry) for entry in self)

    @classmethod
    def constructor(cls, function: Callable[..., Iterator[LDIFEntry]]):
        """Decorator to create an LDIF instance
        from the return values of a function.
        """
        @wraps(function)
        def wrapper(*args, **kwargs):
            """Wraps the original function."""
            return cls(function(*args, **kwargs))

        function.__annotations__['return'] = cls
        return wrapper
