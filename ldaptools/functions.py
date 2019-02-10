"""Miscellaneous functions."""

from grp import getgrall
from pwd import getpwall
from random import choices
from string import ascii_letters, digits
from subprocess import check_output, run
from tempfile import NamedTemporaryFile

from ldaptools.config import CONFIG
from ldaptools.exceptions import IdentifiersExhausted
from ldaptools.ldif import DNComponent, LDIF


__all__ = [
    'slappasswd',
    'ldapadd',
    'genpw',
    'get_uid',
    'get_gid',
    'get_pwhash',
    'domain_components']


SLAPPASSWD = CONFIG['binaries']['slappasswd']
LDAPADD = CONFIG['binaries']['ldapadd']
POOL = range(1000, 65545)


def slappasswd(passwd):
    """Hashes a plain text password for LDIF."""

    return check_output((SLAPPASSWD, '-s', passwd)).decode().strip()


def ldapadd(cn, ldif):  # pylint: disable=C0103
    """Adds the respective LDIF file."""

    if isinstance(ldif, LDIF):
        with NamedTemporaryFile('w', suffix='.ldif') as tmp:
            tmp.write(str(ldif))
            tmp.flush()
            return ldapadd(cn, tmp.name)

    return run((LDAPADD, '-D', str(cn), '-W', '-f', ldif))


def genpw(pool=ascii_letters+digits, length=8):
    """Generates a unique random password."""

    return ''.join(choices(pool, k=length))


def get_uid(pool=POOL):
    """Returns a unique, unassigned user ID."""

    uids = frozenset(user.pw_uid for user in getpwall())

    for uid in pool:
        if uid not in uids:
            return uid

    raise IdentifiersExhausted('UIDs exhausted.')


def get_gid(pool=POOL):
    """Returns a unique, unassigned group ID."""

    gids = frozenset(group.gr_gid for group in getgrall())

    for gid in pool:
        if gid not in gids:
            return gid

    raise IdentifiersExhausted('GIDs exhausted.')


def get_pwhash(passwd, pwhash):
    """Returns the respective password hash."""

    if passwd is not None and pwhash is None:
        return slappasswd(passwd)

    if passwd is None and pwhash is not None:
        return pwhash

    raise ValueError('Must specify either passwd or pwhash.')


def domain_components(domain):
    """Yields domain components."""

    for domain_component in domain.split(','):
        domain_component = domain_component.strip()

        if domain_component:
            yield DNComponent('dc', domain_component)
