"""LDAP user CLI."""

from argparse import ArgumentParser


__all__ = ['get_args']


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
