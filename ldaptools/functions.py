"""Miscellaneous functions."""

from grp import getgrall
from pwd import getpwall
from random import choices
from string import ascii_letters, digits
from subprocess import CompletedProcess, check_output, run
from tempfile import NamedTemporaryFile
from typing import Optional

from ldaptools.config import CONFIG
from ldaptools.exceptions import IdentifiersExhausted
from ldaptools.ldif import DistinguishedName, LDIF


__all__ = [
    'stripped_str_set',
    'slappasswd',
    'ldapadd',
    'ldapmodify',
    'genpw',
    'get_uid',
    'get_gid',
    'get_pwhash'
]


SLAPPASSWD = CONFIG['binaries']['slappasswd']
LDAPADD = CONFIG['binaries']['ldapadd']
LDAPMODIFY = CONFIG['binaries']['ldapmodify']
LDAPDELETE = CONFIG['binaries']['ldapdelete']
MIN_UID = int(CONFIG['user']['min_uid'])
MAX_UID = int(CONFIG['user']['max_uid'])
MIN_GID = int(CONFIG['group']['min_gid'])
MAX_GID = int(CONFIG['group']['max_gid'])
UID_POOL = range(MIN_UID, MAX_UID)
GID_POOL = range(MIN_GID, MAX_GID)


def stripped_str_set(string: str, *, sep: str = ',') -> set[str]:
    """Returns a set of stripped strings."""

    return set(filter(None, map(str.strip, string.split(sep))))


def slappasswd(passwd: str) -> str:
    """Hashes a plain text password for LDIF."""

    return check_output([SLAPPASSWD, '-s', passwd], text=True).strip()


def ldapadd(master: DistinguishedName, ldif: LDIF) -> CompletedProcess:
    """Adds the respective LDIF file."""

    if isinstance(ldif, LDIF):
        with NamedTemporaryFile('w', suffix='.ldif') as tmp:
            tmp.write(str(ldif))
            tmp.flush()
            return ldapadd(master, tmp.name)

    return run([LDAPADD, '-D', str(master), '-W', '-f', ldif], check=True)


def ldapmodify(master: DistinguishedName, ldif: LDIF) -> CompletedProcess:
    """Adds the respective LDIF file."""

    if isinstance(ldif, LDIF):
        with NamedTemporaryFile('w', suffix='.ldif') as tmp:
            tmp.write(str(ldif))
            tmp.flush()
            return ldapmodify(master, tmp.name)

    return run([LDAPMODIFY, '-D', str(master), '-W', '-f', ldif], check=True)


# pylint: disable=C0103
def ldapdelete(master: DistinguishedName, dn: DistinguishedName) \
                -> CompletedProcess:
    """Adds the respective LDIF file."""

    return run([LDAPDELETE, '-D', str(master), str(dn), '-W'], check=True)


def genpw(*, pool: str = ascii_letters+digits, length: int = 8) -> str:
    """Generates a unique random password."""

    return ''.join(choices(pool, k=length))


def get_uid(pool: range = UID_POOL) -> int:
    """Returns a unique, unassigned user ID."""

    uids = frozenset(user.pw_uid for user in getpwall())

    for uid in pool:
        if uid not in uids:
            return uid

    raise IdentifiersExhausted('UIDs exhausted.')


def get_gid(pool: range = GID_POOL) -> int:
    """Returns a unique, unassigned group ID."""

    gids = frozenset(group.gr_gid for group in getgrall())

    for gid in pool:
        if gid not in gids:
            return gid

    raise IdentifiersExhausted('GIDs exhausted.')


def get_pwhash(*, passwd: Optional[str] = None,
               pwhash: Optional[str] = None) -> str:
    """Returns the respective password hash."""

    if passwd is not None and pwhash is None:
        return slappasswd(passwd)

    if passwd is None and pwhash is not None:
        return pwhash

    raise ValueError('Must specify either passwd or pwhash.')
