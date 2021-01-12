"""LDAP group CLI."""

from argparse import ArgumentParser
from logging import INFO, basicConfig, getLogger
from sys import argv

from ldaptools.cli import LOG_FORMAT
from ldaptools.config import CONFIG
from ldaptools.functions import ldapadd, ldapmodify
from ldaptools.group import create, modify, add, remove
from ldaptools.ldif import DistinguishedName


__all__ = ['main']


LOGGER = getLogger(argv[0])


def _add_parser_add_group(subparsers):
    """Adds a parser for adding groups."""

    parser = subparsers.add_parser('add', help='add a group')
    parser.add_argument('group', help="the group's name")
    parser.add_argument('member', nargs='*', help='a group member')


def _add_parser_modify_group(subparsers):
    """Adds a parser for adding groups."""

    parser = subparsers.add_parser('modify', help='modify a group')
    parser.add_argument('group', help="the group's name")


def _add_parser_add_member(subparsers):
    """Adds a parser for adding members to a group."""

    parser = subparsers.add_parser('add-member', help='add a member to a group')
    parser.add_argument('group', help="the group's name")
    parser.add_argument('member', nargs='+', help='a group member')


def _add_parser_remove_member(subparsers):
    """Adds a parser to delete a user."""

    parser = subparsers.add_parser(
        'remove-member', help='remove a member from a group')
    parser.add_argument('group', help="the group's name")
    parser.add_argument('member', nargs='+', help='a group member')


def get_args():
    """Returns the CLI arguments."""

    parser = ArgumentParser(description='Manage LDAP groups and members.')
    parser.add_argument('-g', '--gid', type=int, help='the group ID')
    parser.add_argument('-o', '--ou', help="the user's organizational unit")
    parser.add_argument('-m', '--domain', help='the LDAP domain')
    subparsers = parser.add_subparsers(dest='action')
    _add_parser_add_group(subparsers)
    _add_parser_modify_group(subparsers)
    _add_parser_add_member(subparsers)
    _add_parser_remove_member(subparsers)
    return parser.parse_args()


def _add(args):
    """Adds an LDAP group."""

    ou = args.ou or CONFIG['group']['ou']
    domain = args.domain or CONFIG['common']['domain']
    ldif = create(args.name, args.gid, args.member, ou=ou, domain=domain)
    master = DistinguishedName.for_master(domain)
    ldapadd(master, ldif)


def _modify(args):
    """Modifies an LDAP group."""

    ou = args.ou or CONFIG['group']['ou']
    domain = args.domain or CONFIG['common']['domain']
    ldif = modify(args.name, gid=args.gid, ou=ou, domain=domain)
    master = DistinguishedName.for_master(domain)
    ldapmodify(master, ldif)


def _add_member(args):
    """Adds a member to an LDAP group."""

    ou = args.ou or CONFIG['group']['ou']
    domain = args.domain or CONFIG['common']['domain']

    for member in args.member:
        ldif = add(args.group, member, ou=ou, domain=domain)
        master = DistinguishedName.for_master(domain)
        ldapmodify(master, ldif)


def _remove_member(args):
    """Removes a member from an LDAP group."""

    ou = args.ou or CONFIG['group']['ou']
    domain = args.domain or CONFIG['common']['domain']

    for member in args.member:
        ldif = remove(args.group, member, ou=ou, domain=domain)
        master = DistinguishedName.for_master(domain)
        ldapmodify(master, ldif)


def main():
    """Main function."""

    args = get_args()
    basicConfig(level=INFO, format=LOG_FORMAT)

    if args.action == 'add':
        _add(args)
    elif args.action == 'modify':
        _modify(args)
    elif args.action == 'add-member':
        _add_member(args)
    elif args.action == 'remove-member':
        _remove_member(args)
    else:
        LOGGER.error('No action specified.')
