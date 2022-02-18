"""User and group management."""

from typing import Iterator, Optional

from ldaptools.config import CONFIG
from ldaptools.functions import classes, get_uid, get_gid, get_pwhash
from ldaptools.ldif import DistinguishedName, LDIF, LDIFEntry


__all__ = ['create', 'modify', 'delete']


def get_cn(first_name: str, last_name: str) -> Optional[str]:
    """Returns the respective common name."""

    if first_name is None and last_name is None:
        return None

    if first_name is not None and last_name is not None:
        return ' '.join((first_name, last_name))

    raise ValueError('Must specify both, first and last name or neither.')


def with_fallback(ou: Optional[str], domain: Optional[str]) -> tuple[str, str]:
    """Returns the OU and domain with fallback values from the config."""

    return (
        CONFIG.get('user', 'ou') if ou is None else ou,
        CONFIG.get('common', 'domain') if domain is None else domain
    )


@LDIF.constructor
def create(
        name: str,
        first_name: str,
        last_name: str,
        *,
        passwd: Optional[str] = None,
        pwhash: Optional[str] = None,
        uid: Optional[int] = None,
        gid: Optional[int] = None,
        home: Optional[str] = None,
        shell: Optional[str] = None,
        ou: Optional[str] = None,
        domain: Optional[str] = None
) -> Iterator[LDIFEntry]:
    """Creates an LDIF representing a new user."""

    ou, domain = with_fallback(ou, domain)
    dn = DistinguishedName.for_user(name, domain, ou=ou)
    yield LDIFEntry('dn', dn)

    for clas in classes(CONFIG.get('user', 'classes', fallback=None)):
        yield LDIFEntry('objectClass', clas)

    yield LDIFEntry('uid', name)
    full_name = ' '.join((first_name, last_name))
    yield LDIFEntry('cn', full_name)
    yield LDIFEntry('sn', last_name)
    yield LDIFEntry('givenName', first_name)
    pwhash = get_pwhash(passwd=passwd, pwhash=pwhash)
    yield LDIFEntry('userPassword', pwhash)

    if shell is None:
        shell = CONFIG.get('user', 'shell')

    yield LDIFEntry('loginShell', shell)
    uid = get_uid() if uid is None else uid
    yield LDIFEntry('uidNumber', uid)
    gid = get_gid() if gid is None else gid
    yield LDIFEntry('gidNumber', gid)

    if home is None:
        home = CONFIG.get('user', 'home')

    home = home.format(name)
    yield LDIFEntry('homeDirectory', home)


@LDIF.constructor
def modify(
        name: str,
        *,
        new_name: Optional[str] = None,
        uid: Optional[int] = None,
        gid: Optional[int] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        passwd: Optional[str] = None,
        pwhash: Optional[str] = None,
        home: Optional[str] = None,
        shell: Optional[str] = None,
        ou: Optional[str] = None,
        domain: Optional[str] = None
) -> Iterator[LDIFEntry]:
    """Creates an LDIF to modify a user."""

    ou, domain = with_fallback(ou, domain)
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
        pwhash = get_pwhash(passwd=passwd, pwhash=pwhash)

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


def delete(
        name: str,
        *,
        ou: Optional[str] = None,
        domain: Optional[str] = None
) -> DistinguishedName:
    """Creates an LDIF to delete a user."""

    ou, domain = with_fallback(ou, domain)
    return DistinguishedName.for_user(name, domain, ou=ou)
