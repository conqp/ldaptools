"""Miscellaneous functions."""

from grp import getgrall
from pwd import getpwall
from random import choice
from string import ascii_letters, digits
from subprocess import check_output, run

from ldaptools.exceptions import IdentifiersExhausted


SLAPPASSWD = '/usr/bin/slappasswd'
LDAPADD = '/usr/bin/ldapadd'
BASH = '/bin/bash'


def slappasswd(passwd):
    """Hashes a plain text password for LDIF."""

    return check_output((SLAPPASSWD, '-s', passwd)).decode().strip()


def ldapadd(common_name, ldif):
    """Adds the respective LDIF file."""

    return run((LDAPADD, '-D', str(common_name), '-W', '-f', ldif))


def genpw(pool=ascii_letters+digits, length=8):
    """Generates a unique random password."""

    return ''.join(choice(pool) for _ in range(length))


def get_uid(min_=1000, max_=65544):
    """Returns a unique, unassigned user ID."""

    uids = set(user.pw_uid for user in getpwall())

    for uid in range(min_, max_):
        if uid not in uids:
            return uid

    raise IdentifiersExhausted('UIDs exhausted.')


def get_gid(min_=1000, max_=65544):
    """Returns a unique, unassigned group ID."""

    gids = set(group.gr_gid for group in getgrall())

    for gid in range(min_, max_):
        if gid not in gids:
            return gid

    raise IdentifiersExhausted('GIDs exhausted.')
