"""Group LDIFs."""

from ldaptools.config import CONFIG
from ldaptools.functions import domain_components
from ldaptools.ldif import DistinguishedName, DNComponent, LDIF, LDIFEntry


CLASSES = tuple(filter(None, map(
    lambda item: item.strip(), CONFIG['group']['classes'].split(','))))
DOMAIN = CONFIG['common']['domain']
OU = CONFIG['group']['ou']


def get_dn(dn, name):   # pylint: disable=C0103
    """Returns a distinguished name with group name and ou information."""

    dn = DistinguishedName(dn)
    uid_entry = DNComponent('cn', name)
    dn.insert(0, uid_entry)
    return dn


@LDIF.constructor
def create(name, gid, members, *, ou=OU, domain=DOMAIN):
    """Creates a new group LDIF."""

    dc = domain_components(domain)
    dn = DistinguishedName.group(name, *dc, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('cn', name)
    yield LDIFEntry('gidNumber', gid)

    for clas in CLASSES:
        yield LDIFEntry('objectClass', clas)

    for member in members:
        yield LDIFEntry('memberUid', member)


@LDIF.constructor
def modify(name, new_name=None, gid=None, *, ou=OU, domain=DOMAIN):
    """Modifies an existing group."""

    dc = domain_components(domain)
    dn = DistinguishedName.group(name, *dc, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')

    if new_name is not None:
        yield LDIFEntry('replace', 'cn')
        yield LDIFEntry('cn', new_name)

    if gid is not None:
        yield LDIFEntry('replace', 'gidNumber')
        yield LDIFEntry('gidNumber', gid)


@LDIF.constructor
def add(name, member, *, ou=OU, domain=DOMAIN):
    """Adds a member to the group."""

    dc = domain_components(domain)
    dn = DistinguishedName.group(name, *dc, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')
    yield LDIFEntry('add', 'memberUid')
    yield LDIFEntry('memberUid', member)


@LDIF.constructor
def remove(name, member, *, ou=OU, domain=DOMAIN):
    """Adds a member to the group."""

    dc = domain_components(domain)
    dn = DistinguishedName.group(name, *dc, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')
    yield LDIFEntry('delete', 'memberUid')
    yield LDIFEntry('memberUid', member)
