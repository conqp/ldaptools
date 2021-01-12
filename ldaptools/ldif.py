"""LDIF file models."""

from __future__ import annotations
from functools import wraps
from os import linesep
from typing import Iterator, NamedTuple

from ldaptools.config import CONFIG


__all__ = ['DistinguishedName', 'DNComponent', 'LDIF', 'LDIFEntry']

USER_OU = CONFIG.get('user', 'ou', fallback=None)
GROUP_OU = CONFIG.get('group', 'ou', fallback=None)
MASTER_CN = CONFIG.get('common', 'master', fallback=None)


# pylint: disable=C0103
def domain_components(domain: str) -> Iterator[DNComponent]:
    """Yields domain components."""

    for domain_component in domain.split('.'):
        if domain_component:
            yield DNComponent('dc', domain_component)


class DistinguishedName(list):
    """Represents a distinguished name."""

    def __str__(self):
        """Returns a string representation of the distinguished name."""
        return ','.join(str(component) for component in self)

    @classmethod
    def for_user(cls, uid: str, domain: str, *,
                 ou: str = USER_OU) -> DistinguishedName:
        """Creates a distinguished name for a user."""
        uid = DNComponent('uid', uid)
        ou = DNComponent('ou', ou)
        return cls((uid, ou, *domain_components(domain)))

    @classmethod
    def for_group(cls, cn: str, domain: str, *,
                  ou: str = GROUP_OU) -> DistinguishedName:
        """Creates a distinguished name for a group."""
        cn = DNComponent('cn', cn)
        ou = DNComponent('ou', ou)
        return cls((cn, ou, *domain_components(domain)))

    @classmethod
    def for_master(cls, domain: str, *,
                   cn: str = MASTER_CN) -> DistinguishedName:
        """Creates a distinguished name for administrative operations."""
        cn = DNComponent('cn', cn)
        return cls((cn, *domain_components(domain)))


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

        function.__annotations__['return'] = cls
        return wrapper


class LDIFEntry(NamedTuple):
    """An LDIF file's entry."""

    key: str
    value: str

    def __str__(self):
        return f'{self.key}: {self.value}'
