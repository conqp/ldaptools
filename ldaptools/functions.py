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
    'classes',
    'slappasswd',
    'ldapadd',
    'ldapmodify',
    'genpw',
    'get_uid',
    'get_gid',
    'get_pwhash'
]

SLAPPASSWD = '/usr/bin/slappasswd'
LDAPADD = '/usr/bin/ldapadd'
LDAPMODIFY = '/usr/bin/ldapmodify'
LDAPDELETE = '/usr/bin/ldapdelete'


def classes(string: Optional[str], *, sep: str = ',') -> set[str]:
    """Returns a set of stripped class names."""

    if string is None:
        return set()

    return set(filter(None, map(str.strip, string.split(sep))))


def slappasswd(passwd: str) -> str:
    """Hashes a plain text password for LDIF."""

    binary = CONFIG.get('binaries', 'slappasswd', fallback=SLAPPASSWD)
    return check_output([binary, '-s', passwd], text=True).strip()


def ldapadd(master: DistinguishedName, ldif: LDIF) -> CompletedProcess:
    """Adds the respective LDIF file."""

    if isinstance(ldif, LDIF):
        with NamedTemporaryFile('w', suffix='.ldif') as tmp:
            tmp.write(str(ldif))
            tmp.flush()
            return ldapadd(master, tmp.name)

    binary = CONFIG.get('binaries','ldapadd', fallback=LDAPADD)
    return run([binary, '-D', str(master), '-W', '-f', ldif], check=True)


def ldapmodify(master: DistinguishedName, ldif: LDIF) -> CompletedProcess:
    """Adds the respective LDIF file."""

    if isinstance(ldif, LDIF):
        with NamedTemporaryFile('w', suffix='.ldif') as tmp:
            tmp.write(str(ldif))
            tmp.flush()
            return ldapmodify(master, tmp.name)

    binary = CONFIG.get('binaries', 'ldapmodify', fallback=LDAPMODIFY)
    return run([binary, '-D', str(master), '-W', '-f', ldif], check=True)


# pylint: disable=C0103
def ldapdelete(master: DistinguishedName, dn: DistinguishedName) \
                -> CompletedProcess:
    """Adds the respective LDIF file."""

    binary = CONFIG.get('binaries', 'ldapdelete', fallback=LDAPDELETE)
    return run([binary, '-D', str(master), str(dn), '-W'], check=True)


def genpw(*, pool: str = ascii_letters+digits, length: int = 8) -> str:
    """Generates a unique random password."""

    return ''.join(choices(pool, k=length))


def get_uid(*, pool: Optional[range] = None) -> int:
    """Returns a unique, unassigned user ID."""

    if pool is None:
        pool = range(CONFIG.getint('user', 'min_uid', fallback=2000),
                     CONFIG.getint('user', 'max_uid', fallback=65545))

    uids = frozenset(user.pw_uid for user in getpwall())

    for uid in pool:
        if uid not in uids:
            return uid

    raise IdentifiersExhausted('UIDs exhausted.')


def get_gid(*, pool: Optional[range] = None) -> int:
    """Returns a unique, unassigned group ID."""

    if pool is None:
        pool = range(CONFIG.getint('group', 'min_gid', fallback=2000),
                     CONFIG.getint('group', 'max_gid', fallback=65545))

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
