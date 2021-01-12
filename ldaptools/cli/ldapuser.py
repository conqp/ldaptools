"""LDAP user CLI."""

from argparse import ArgumentParser
from logging import INFO, basicConfig, getLogger
from sys import argv

from ldaptools.cli import LOG_FORMAT
from ldaptools.config import CONFIG
from ldaptools.functions import ldapadd, ldapmodify, ldapdelete, genpw
from ldaptools.user import create, modify, delete
from ldaptools.ldif import DistinguishedName


__all__ = ['main']


LOGGER = getLogger(argv[0])


def _add_parser_add_user(subparsers):
    """Adds a parser for adding users."""

    parser = subparsers.add_parser('add', help='add a user')
    parser.add_argument('user_name', help='the user name')
    parser.add_argument('first_name', help="the user's first name")
    parser.add_argument('last_name', help="the user's last name")


def _add_parser_modify_user(subparsers):
    """Adds a parser for modifying users."""

    parser = subparsers.add_parser('modify', help='modify a user')
    parser.add_argument('user_name', help='the user name')
    parser.add_argument('first_name', nargs='?', help="the user's first name")
    parser.add_argument('last_name', nargs='?', help="the user's last name")


def _add_parser_delete_user(subparsers):
    """Adds a parser to delete a user."""

    parser = subparsers.add_parser('delete', help='delete a user')
    parser.add_argument('user_name', help='the user name')


def get_args():
    """Returns the CLI arguments."""

    parser = ArgumentParser(description='Manage LDAP users.')
    parser.add_argument('-p', '--passwd', help="the user's password")
    parser.add_argument('-u', '--uid', type=int, help="the user's user ID")
    parser.add_argument('-g', '--gid', type=int, help="the user's group ID")
    parser.add_argument('-s', '--shell', help="the user's shell")
    parser.add_argument('-d', '--home', help="the user's home directory")
    parser.add_argument('-o', '--ou', help="the user's organizational unit")
    parser.add_argument('-m', '--domain', help='the LDAP domain')
    subparsers = parser.add_subparsers(dest='action')
    _add_parser_add_user(subparsers)
    _add_parser_modify_user(subparsers)
    _add_parser_delete_user(subparsers)
    return parser.parse_args()


def _add(args):
    """Adds an LDAP user."""

    shell = args.shell or CONFIG['user']['shell']
    home = args.home or CONFIG['user']['home']
    ou = args.ou or CONFIG['user']['ou']
    domain = args.domain or CONFIG['common']['domain']

    if args.passwd:
        passwd = args.passwd
    else:
        passwd = genpw()
        LOGGER.info('Generated password: %s', passwd)

    ldif = create(
        args.user_name, args.first_name, args.last_name, passwd=passwd,
        uid=args.uid, gid=args.gid, home=home, shell=shell, ou=ou,
        domain=domain)
    master = DistinguishedName.for_master(domain)
    ldapadd(master, ldif)


def _modify(args):
    """Modifies an LDAP user."""

    ou = args.ou or CONFIG['user']['ou']
    domain = args.domain or CONFIG['common']['domain']
    ldif = modify(
        args.user_name, first_name=args.first_name, last_name=args.last_name,
        passwd=args.passwd, uid=args.uid, gid=args.gid, home=args.home,
        shell=args.shell, ou=ou, domain=domain)
    master = DistinguishedName.for_master(domain)
    ldapmodify(master, ldif)


def _delete(args):
    """Deletes the respective user."""

    ou = args.ou or CONFIG['user']['ou']
    domain = args.domain or CONFIG['common']['domain']
    dn = delete(args.user_name, ou=ou, domain=domain)
    master = DistinguishedName.for_master(domain)
    ldapdelete(master, dn)


def main():
    """Main function."""

    args = get_args()
    basicConfig(level=INFO, format=LOG_FORMAT)

    if args.action == 'add':
        _add(args)
    elif args.action == 'modify':
        _modify(args)
    elif args.action == 'delete':
        _delete(args)
    else:
        LOGGER.error('No action specified.')
