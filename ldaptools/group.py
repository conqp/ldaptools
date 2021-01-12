"""Group LDIFs."""

from typing import Iterable, Iterator, Optional

from ldaptools.config import CONFIG
from ldaptools.functions import stripped_str_set
from ldaptools.ldif import DistinguishedName, DNComponent, LDIF, LDIFEntry


CLASSES = stripped_str_set(CONFIG.get('group', 'classes', fallback=''))
DOMAIN = CONFIG.get('common', 'domain', fallback=None)
OU = CONFIG.get('group', 'ou', fallback=None)


# pylint: disable=C0103
def get_dn(dn: str, name: str) -> DistinguishedName:
    """Returns a distinguished name with group name and ou information."""

    dn = DistinguishedName(dn)
    uid_entry = DNComponent('cn', name)
    dn.insert(0, uid_entry)
    return dn


@LDIF.constructor
def create(name: str, gid: int, members: Iterable[str], *,
           ou: str = OU, domain: str = DOMAIN) -> Iterator[LDIFEntry]:
    """Creates a new group LDIF."""

    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('cn', name)
    yield LDIFEntry('gidNumber', gid)

    for clas in CLASSES:
        yield LDIFEntry('objectClass', clas)

    for member in members:
        yield LDIFEntry('memberUid', member)


@LDIF.constructor
def modify(name: str, new_name: Optional[str] = None,
           gid: Optional[int] = None, *, ou: str = OU,
           domain: str = DOMAIN) -> Iterator[LDIFEntry]:
    """Modifies an existing group."""

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
def add(name: str, member: str, *, ou: str = OU,
        domain: str = DOMAIN) -> Iterator[LDIFEntry]:
    """Adds a member to the group."""

    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')
    yield LDIFEntry('add', 'memberUid')
    yield LDIFEntry('memberUid', member)


@LDIF.constructor
def remove(name: str, member: str, *, ou: str = OU,
           domain: str = DOMAIN) -> Iterator[LDIFEntry]:
    """Adds a member to the group."""

    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')
    yield LDIFEntry('delete', 'memberUid')
    yield LDIFEntry('memberUid', member)
