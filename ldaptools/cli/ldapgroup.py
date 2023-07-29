"""LDAP group CLI."""

from argparse import ArgumentParser, Namespace, _SubParsersAction
from subprocess import CalledProcessError
from logging import INFO, basicConfig

from ldaptools.config import CONFIG, CONFIG_FILE
from ldaptools.functions import ldapadd, ldapdelete, ldapmodify
from ldaptools.group import add, create, delete, modify, remove
from ldaptools.ldif import DistinguishedName
from ldaptools.logging import LOG_FORMAT, LOGGER


__all__ = ["main"]


def _add_parser_add_group(subparsers: _SubParsersAction) -> None:
    """Adds a parser for adding groups."""

    parser = subparsers.add_parser("add", help="add a group")
    parser.add_argument("group", help="the group's name")
    parser.add_argument("member", nargs="*", help="a group member")


def _add_parser_modify_group(subparsers: _SubParsersAction) -> None:
    """Adds a parser for adding groups."""

    parser = subparsers.add_parser("modify", help="modify a group")
    parser.add_argument("group", help="the group's name")


def _add_parser_add_member(subparsers: _SubParsersAction) -> None:
    """Adds a parser for adding members to a group."""

    parser = subparsers.add_parser("add-member", help="add a member to a group")
    parser.add_argument("group", help="the group's name")
    parser.add_argument("member", nargs="+", help="a group member")


def _add_parser_remove_member(subparsers: _SubParsersAction) -> None:
    """Adds a parser to delete a user from the group."""

    parser = subparsers.add_parser("remove-member", help="remove a member from a group")
    parser.add_argument("group", help="the group's name")
    parser.add_argument("member", nargs="+", help="a group member")


def _add_parser_delete_group(subparsers: _SubParsersAction) -> None:
    """Adds a parser to delete a group."""

    parser = subparsers.add_parser("delete", help="delete a group")
    parser.add_argument("group", help="the group's name")


def get_args() -> Namespace:
    """Returns the CLI arguments."""

    parser = ArgumentParser(description="Manage LDAP groups and members.")
    parser.add_argument("-g", "--gid", type=int, help="the group ID")
    parser.add_argument("-o", "--ou", help="the user's organizational unit")
    parser.add_argument("-m", "--domain", help="the LDAP domain")
    subparsers = parser.add_subparsers(dest="action")
    _add_parser_add_group(subparsers)
    _add_parser_modify_group(subparsers)
    _add_parser_add_member(subparsers)
    _add_parser_remove_member(subparsers)
    _add_parser_delete_group(subparsers)
    return parser.parse_args()


def _add(args: Namespace) -> int:
    """Adds an LDAP group."""

    ou = args.ou or CONFIG.get("group", "ou")
    domain = args.domain or CONFIG.get("common", "domain")
    ldif = create(args.group, args.gid, args.member, ou=ou, domain=domain)
    master = DistinguishedName.for_master(domain)

    try:
        ldapadd(master, ldif)
    except CalledProcessError as error:
        return error.returncode

    return 0


def _modify(args: Namespace) -> int:
    """Modifies an LDAP group."""

    ou = args.ou or CONFIG.get("group", "ou")
    domain = args.domain or CONFIG.get("common", "domain")
    ldif = modify(args.group, gid=args.gid, ou=ou, domain=domain)
    master = DistinguishedName.for_master(domain)

    try:
        ldapmodify(master, ldif)
    except CalledProcessError as error:
        return error.returncode

    return 0


def _add_member(args: Namespace) -> int:
    """Adds a member to an LDAP group."""

    ou = args.ou or CONFIG.get("group", "ou")
    domain = args.domain or CONFIG.get("common", "domain")
    return_code = 0

    for member in args.member:
        try:
            ldif = add(args.group, member, ou=ou, domain=domain)
            master = DistinguishedName.for_master(domain)
            ldapmodify(master, ldif)
        except CalledProcessError as error:
            LOGGER.error("Could not add member: %s", member)
            return_code = error.returncode

    return return_code


def _remove_member(args: Namespace) -> int:
    """Removes a member from an LDAP group."""

    ou = args.ou or CONFIG.get("group", "ou")
    domain = args.domain or CONFIG.get("common", "domain")
    return_code = 0

    for member in args.member:
        try:
            ldif = remove(args.group, member, ou=ou, domain=domain)
            master = DistinguishedName.for_master(domain)
            ldapmodify(master, ldif)
        except CalledProcessError as error:
            LOGGER.error("Could not add member: %s", member)
            return_code = error.returncode

    return return_code


def _delete(args: Namespace) -> int:
    """Deletes the respective user."""

    ou = args.ou or CONFIG.get("group", "ou")
    domain = args.domain or CONFIG.get("common", "domain")
    dn = delete(args.group, ou=ou, domain=domain)
    master = DistinguishedName.for_master(domain)

    try:
        ldapdelete(master, dn)
    except CalledProcessError as error:
        return error.returncode

    return 0


def main() -> int:
    """Main function."""

    args = get_args()
    basicConfig(level=INFO, format=LOG_FORMAT)
    CONFIG.read(CONFIG_FILE)

    if args.action == "add":
        return _add(args)

    if args.action == "modify":
        return _modify(args)

    if args.action == "add-member":
        return _add_member(args)

    if args.action == "remove-member":
        return _remove_member(args)

    if args.action == "delete":
        return _delete(args)

    LOGGER.error("No action specified.")
    return 3
