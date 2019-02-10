"""Group LDIFs."""

from ldaptools.constants import GROUP_CLASSES, GROUP_OU
from ldaptools.ldif import DistinguishedName, DNComponent, LDIF, LDIFEntry


def get_dn(dn, name, ou):   # pylint: disable=C0103
    """Returns a distinguished name with group name and ou information."""

    dn = DistinguishedName(dn)
    uid_entry = DNComponent('cn', name)
    dn.insert(0, uid_entry)
    ou_entry = DNComponent('ou', ou)
    dn.insert(1, ou_entry)
    return dn


@LDIF.constructor
def create(dn, name, gid, members, *, ou=GROUP_OU):
    """Creates a new group LDIF."""

    dn = get_dn(dn, name, ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('cn', name)
    yield LDIFEntry('gidNumber', gid)

    for clas in GROUP_CLASSES:
        yield LDIFEntry('objectClass', clas)

    for member in members:
        yield LDIFEntry('memberUid', member)


@LDIF.constructor
def modify(dn, name, new_name=None, gid=None, *, ou=GROUP_OU):
    """Modifies an existing group."""

    dn = get_dn(dn, name, ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')

    if new_name is not None:
        yield LDIFEntry('replace', 'cn')
        yield LDIFEntry('cn', new_name)

    if gid is not None:
        yield LDIFEntry('replace', 'gidNumber')
        yield LDIFEntry('gidNumber', gid)


@LDIF.constructor
def add(dn, name, member, *, ou=GROUP_OU):
    """Adds a member to the group."""

    dn = get_dn(dn, name, ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')
    yield LDIFEntry('add', 'memberUid')
    yield LDIFEntry('memberUid', member)


@LDIF.constructor
def remove(dn, name, member, *, ou=GROUP_OU):
    """Adds a member to the group."""

    dn = get_dn(dn, name, ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')
    yield LDIFEntry('delete', 'memberUid')
    yield LDIFEntry('memberUid', member)
