"""Group LDIFs."""

from typing import Iterable, Iterator

from ldaptools.config import CONFIG
from ldaptools.functions import classes
from ldaptools.ldif import DistinguishedName, DNComponent, LDIF, LDIFEntry


__all__ = ["create", "modify", "add", "remove", "delete"]


def get_dn(dn: str, name: str) -> DistinguishedName:
    """Returns a distinguished name with group name and ou information."""

    dn = DistinguishedName(dn)
    uid_entry = DNComponent("cn", name)
    dn.insert(0, uid_entry)
    return dn


def with_fallback(ou: str | None, domain: str | None) -> tuple[str, str]:
    """Returns the ou and domain with fallback on defaults from config."""

    ou = CONFIG.get("group", "ou") if ou is None else ou
    domain = CONFIG.get("common", "domain") if domain is None else domain
    return ou, domain


@LDIF.constructor
def create(
    name: str,
    gid: int,
    members: Iterable[str],
    *,
    ou: str | None = None,
    domain: str | None = str
) -> Iterator[LDIFEntry]:
    """Creates a new group LDIF."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry("dn", dn)
    yield LDIFEntry("cn", name)
    yield LDIFEntry("gidNumber", gid)

    for clas in classes(CONFIG.get("group", "classes", fallback=None)):
        yield LDIFEntry("objectClass", clas)

    for member in members:
        yield LDIFEntry("memberUid", member)


@LDIF.constructor
def modify(
    name: str,
    new_name: str | None = None,
    gid: int | None = None,
    *,
    ou: str | None = None,
    domain: str | None = None
) -> Iterator[LDIFEntry]:
    """Modifies an existing group."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry("dn", dn)
    yield LDIFEntry("changetype", "modify")

    if new_name is not None:
        yield LDIFEntry("replace", "cn")
        yield LDIFEntry("cn", new_name)

    if gid is not None:
        yield LDIFEntry("replace", "gidNumber")
        yield LDIFEntry("gidNumber", gid)


@LDIF.constructor
def add(
    name: str, member: str, *, ou: str | None = None, domain: str | None = None
) -> Iterator[LDIFEntry]:
    """Adds a member to the group."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry("dn", dn)
    yield LDIFEntry("changetype", "modify")
    yield LDIFEntry("add", "memberUid")
    yield LDIFEntry("memberUid", member)


@LDIF.constructor
def remove(
    name: str, member: str, *, ou: str | None = None, domain: str | None = None
) -> Iterator[LDIFEntry]:
    """Removes a member from the group."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_group(name, domain, ou=ou)
    yield LDIFEntry("dn", dn)
    yield LDIFEntry("changetype", "modify")
    yield LDIFEntry("delete", "memberUid")
    yield LDIFEntry("memberUid", member)


def delete(
    name: str, *, ou: str | None = None, domain: str | None = None
) -> DistinguishedName:
    """Removes a member from the group."""

    ou, domain = with_fallback(ou, domain)
    return DistinguishedName.for_group(name, domain, ou=ou)
