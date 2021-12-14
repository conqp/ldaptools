"""Group LDIFs."""

from typing import Iterable, Iterator, Optional

from ldaptools.config import CONFIG
from ldaptools.functions import classes
from ldaptools.ldif import DistinguishedName, DNComponent, LDIF, LDIFEntry


# pylint: disable=C0103
def get_dn(dn: str, name: str) -> DistinguishedName:
    """Returns a distinguished name with group name and ou information."""

    dn = DistinguishedName(dn)
    uid_entry = DNComponent('cn', name)
    dn.insert(0, uid_entry)
    return dn


def with_fallback(ou: Optional[str], domain: Optional[str]) -> tuple[str, str]:
    """Returns the ou and domain with fallback on defaults from config."""

    ou = CONFIG.get('group', 'ou') if ou is None else ou
    domain = CONFIG.get('common', 'domain') if domain is None else domain
    return (ou, domain)


@LDIF.constructor
def create(name: str, gid: int, members: Iterable[str], *,
           ou: Optional[str] = None,
           domain: Optional[str] = str) -> Iterator[LDIFEntry]:
    """Creates a new group LDIF."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('cn', name)
    yield LDIFEntry('gidNumber', gid)

    for clas in classes(CONFIG.get('group', 'classes', fallback=None)):
        yield LDIFEntry('objectClass', clas)

    for member in members:
        yield LDIFEntry('memberUid', member)


@LDIF.constructor
def modify(name: str, new_name: Optional[str] = None,
           gid: Optional[int] = None, *, ou: Optional[str] = None,
           domain: Optional[str] = None) -> Iterator[LDIFEntry]:
    """Modifies an existing group."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')

    if new_name is not None:
        yield LDIFEntry('replace', 'cn')
        yield LDIFEntry('cn', new_name)

    if gid is not None:
        yield LDIFEntry('replace', 'gidNumber')
        yield LDIFEntry('gidNumber', gid)


@LDIF.constructor
def add(name: str, member: str, *, ou: Optional[str] = None,
        domain: Optional[str] = None) -> Iterator[LDIFEntry]:
    """Adds a member to the group."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')
    yield LDIFEntry('add', 'memberUid')
    yield LDIFEntry('memberUid', member)


@LDIF.constructor
def remove(name: str, member: str, *, ou: Optional[str] = None,
           domain: Optional[str] = None) -> Iterator[LDIFEntry]:
    """Adds a member to the group."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')
    yield LDIFEntry('delete', 'memberUid')
    yield LDIFEntry('memberUid', member)
