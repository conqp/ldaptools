"""Miscellaneous functions."""

from grp import getgrall
from pathlib import Path
from pwd import getpwall
from secrets import choice
from string import ascii_letters, digits
from subprocess import CompletedProcess, check_output, run
from tempfile import NamedTemporaryFile

from ldaptools.config import CONFIG
from ldaptools.exceptions import IdentifiersExhausted
from ldaptools.ldif import DistinguishedName, LDIF


__all__ = [
    'classes',
    'slappasswd',
    'ldapadd',
    'ldapdelete',
    'ldapmodify',
    'genpw',
    'get_uid',
    'get_gid',
    'get_pwhash'
]

ID_MIN: int = 2000
ID_MAX: int = 65545
SLAPPASSWD: str = '/usr/bin/slappasswd'
LDAPADD: str = '/usr/bin/ldapadd'
LDAPMODIFY: str = '/usr/bin/ldapmodify'
LDAPDELETE: str = '/usr/bin/ldapdelete'


def classes(string: str | None, *, sep: str = ',') -> set[str]:
    """Returns a set of stripped class names."""

    if string is None:
        return set()

    return set(filter(None, map(str.strip, string.split(sep))))


def slappasswd(passwd: str) -> str:
    """Hashes a plain text password for LDIF."""

    return check_output(
        [
            CONFIG.get('binaries', 'slappasswd', fallback=SLAPPASSWD),
            '-s',
            passwd
        ],
        text=True
    ).strip()


def ldapadd(
        master: DistinguishedName,
        ldif: LDIF | Path | str
) -> CompletedProcess:
    """Adds the respective LDIF file."""

    if isinstance(ldif, LDIF):
        with NamedTemporaryFile('w', suffix='.ldif') as tmp:
            tmp.write(str(ldif))
            tmp.flush()
            return ldapadd(master, tmp.name)

    return run(
        [
            CONFIG.get('binaries', 'ldapadd', fallback=LDAPADD),
            '-D',
            str(master),
            '-W',
            '-f',
            str(ldif)
        ],
        check=True
    )


def ldapmodify(
        master: DistinguishedName,
        ldif: LDIF | Path | str
) -> CompletedProcess:
    """Adds the respective LDIF file."""

    if isinstance(ldif, LDIF):
        with NamedTemporaryFile('w', suffix='.ldif') as tmp:
            tmp.write(str(ldif))
            tmp.flush()
            return ldapmodify(master, tmp.name)

    return run(
        [
            CONFIG.get('binaries', 'ldapmodify', fallback=LDAPMODIFY),
            '-D',
            str(master),
            '-W',
            '-f',
            str(ldif)
        ],
        check=True
    )


def ldapdelete(
        master: DistinguishedName,
        dn: DistinguishedName
) -> CompletedProcess:
    """Adds the respective LDIF file."""

    return run(
        [
            CONFIG.get('binaries', 'ldapdelete', fallback=LDAPDELETE),
            '-D',
            str(master),
            str(dn),
            '-W'
        ],
        check=True
    )


def genpw(*, pool: str = ascii_letters+digits, length: int = 8) -> str:
    """Generates a unique random password."""

    return ''.join(choice(pool) for _ in range(length))


def get_gid(*, pool: range | None = None) -> int:
    """Returns a unique, unassigned group ID."""

    return _get_unique_identifier(
        range(
            CONFIG.getint('group', 'min_gid', fallback=ID_MIN),
            CONFIG.getint('group', 'max_gid', fallback=ID_MAX)
        ) if pool is None else pool,
        set(group.gr_gid for group in getgrall()),
        'GID'
    )


def get_uid(*, pool: range | None = None) -> int:
    """Returns a unique, unassigned user ID."""

    return _get_unique_identifier(
        range(
            CONFIG.getint('user', 'min_uid', fallback=ID_MIN),
            CONFIG.getint('user', 'max_uid', fallback=ID_MAX)
        ) if pool is None else pool,
        set(user.pw_uid for user in getpwall()),
        'UID'
    )


def get_pwhash(
        *,
        passwd: str | None = None,
        pwhash: str | None = None
) -> str:
    """Returns the respective password hash."""

    if passwd is not None and pwhash is None:
        return slappasswd(passwd)

    if passwd is None and pwhash is not None:
        return pwhash

    raise ValueError('Must specify either passwd or pwhash.')


def _get_unique_identifier(pool: range, used: set[int], name: str) -> int:
    """Return a unique identifier from the given pool."""

    for ident in pool:
        if ident not in used:
            return ident

    raise IdentifiersExhausted(f'{name}s exhausted.')
