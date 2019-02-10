"""User and group management."""

from ldaptools.config import CONFIG
from ldaptools.functions import get_uid, get_gid, get_pwhash
from ldaptools.ldif import DistinguishedName, LDIF, LDIFEntry


__all__ = ['create', 'modify']


DOMAIN = CONFIG['common']['domain']
CLASSES = tuple(filter(None, map(
    lambda item: item.strip(), CONFIG['user']['classes'].split(','))))
HOME = CONFIG['user']['home']
OU = CONFIG['user']['ou']
SHELL = CONFIG['user']['shell']


def get_cn(first_name, last_name):
    """Returns the respective common name."""

    if first_name is None and last_name is None:
        return None

    if first_name is not None and last_name is not None:
        return ' '.join((first_name, last_name))

    raise ValueError('Must specify both, first and last name or neither.')


@LDIF.constructor
def create(name, first_name, last_name, passwd=None, pwhash=None, uid=None,
           gid=None, home=HOME, shell=SHELL, *, ou=OU, domain=DOMAIN):
    """Creates an LDIF represeting a new user."""

    dn = DistinguishedName.for_user(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)

    for clas in CLASSES:
        yield LDIFEntry('objectClass', clas)

    yield LDIFEntry('uid', name)
    full_name = ' '.join((first_name, last_name))
    yield LDIFEntry('cn', full_name)
    yield LDIFEntry('sn', last_name)
    yield LDIFEntry('givenName', first_name)
    pwhash = get_pwhash(passwd, pwhash)
    yield LDIFEntry('userPassword', pwhash)
    yield LDIFEntry('loginShell', shell)
    uid = get_uid() if uid is None else uid
    yield LDIFEntry('uidNumber', uid)
    gid = get_gid() if gid is None else gid
    yield LDIFEntry('gidNumber', gid)
    home = home.format(name)
    yield LDIFEntry('homeDirectory', home)


@LDIF.constructor
def modify(name=None, new_name=None, uid=None, gid=None, first_name=None,
           last_name=None, passwd=None, pwhash=None, home=None, shell=None, *,
           ou=OU, domain=DOMAIN):
    """Creates an LDIF to modify a user."""

    dn = DistinguishedName.for_user(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)
    yield LDIFEntry('changetype', 'modify')

    if new_name is not None:
        yield LDIFEntry('replace', 'uid')
        yield LDIFEntry('uid', new_name)

    cn = get_cn(first_name, last_name)

    if cn is not None:
        yield LDIFEntry('replace', 'cn')
        yield LDIFEntry('cn', cn)

    if last_name is not None:
        yield LDIFEntry('replace', 'sn')
        yield LDIFEntry('sn', last_name)

    if first_name is not None:
        yield LDIFEntry('replace', 'givenName')
        yield LDIFEntry('givenName', first_name)

    if pwhash is None and passwd is None:
        pwhash = None
    else:
        pwhash = get_pwhash(passwd, pwhash)

    if pwhash is not None:
        yield LDIFEntry('replace', 'userPassword')
        yield LDIFEntry('userPassword', pwhash)

    if shell is not None:
        yield LDIFEntry('replace', 'loginShell')
        yield LDIFEntry('loginShell', shell)

    if uid is not None:
        yield LDIFEntry('replace', 'uidNumber')
        yield LDIFEntry('uidNumber', uid)

    if gid is not None:
        yield LDIFEntry('replace', 'gidNumber')
        yield LDIFEntry('gidNumber', gid)

    if home is not None:
        yield LDIFEntry('replace', 'homeDirectory')
        yield LDIFEntry('homeDirectory', home)


def delete(name, *, ou=OU, domain=DOMAIN):
    """Creates an LDIF to delete a user."""

    return DistinguishedName.for_user(name, domain, ou=ou)
