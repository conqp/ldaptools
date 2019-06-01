"""LDAP group CLI."""

from argparse import ArgumentParser


__all__ = ['get_args']


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
