"""LDAP user CLI."""

from argparse import ArgumentParser, Namespace, _SubParsersAction
from subprocess import CalledProcessError
from logging import INFO, basicConfig

from ldaptools.config import CONFIG, CONFIG_FILE
from ldaptools.functions import ldapadd, ldapmodify, ldapdelete, genpw
from ldaptools.user import create, modify, delete
from ldaptools.ldif import DistinguishedName
from ldaptools.logging import LOG_FORMAT, LOGGER


__all__ = ["main"]


def _add_parser_add_user(subparsers: _SubParsersAction) -> None:
    """Adds a parser for adding users."""

    parser = subparsers.add_parser("add", help="add a user")
    parser.add_argument("user_name", help="the user name")
    parser.add_argument("first_name", help="the user's first name")
    parser.add_argument("last_name", help="the user's last name")


def _add_parser_modify_user(subparsers: _SubParsersAction) -> None:
    """Adds a parser for modifying users."""

    parser = subparsers.add_parser("modify", help="modify a user")
    parser.add_argument("user_name", help="the user name")
    parser.add_argument("first_name", nargs="?", help="the user's first name")
    parser.add_argument("last_name", nargs="?", help="the user's last name")


def _add_parser_delete_user(subparsers: _SubParsersAction) -> None:
    """Adds a parser to delete a user."""

    parser = subparsers.add_parser("delete", help="delete a user")
    parser.add_argument("user_name", help="the user name")


def get_args() -> Namespace:
    """Returns the CLI arguments."""

    parser = ArgumentParser(description="Manage LDAP users.")
    parser.add_argument("-p", "--passwd", help="the user's password")
    parser.add_argument("-u", "--uid", type=int, help="the user's user ID")
    parser.add_argument("-g", "--gid", type=int, help="the user's group ID")
    parser.add_argument("-s", "--shell", help="the user's shell")
    parser.add_argument("-d", "--home", help="the user's home directory")
    parser.add_argument("-o", "--ou", help="the user's organizational unit")
    parser.add_argument("-m", "--domain", help="the LDAP domain")
    subparsers = parser.add_subparsers(dest="action")
    _add_parser_add_user(subparsers)
    _add_parser_modify_user(subparsers)
    _add_parser_delete_user(subparsers)
    return parser.parse_args()


def _add(args: Namespace) -> int:
    """Adds an LDAP user."""

    shell = args.shell or CONFIG.get("user", "shell")
    home = args.home or CONFIG.get("user", "home")
    ou = args.ou or CONFIG.get("user", "ou")
    domain = args.domain or CONFIG.get("common", "domain")

    if args.passwd:
        passwd = args.passwd
    else:
        passwd = genpw()
        LOGGER.info("Generated password: %s", passwd)

    try:
        ldif = create(
            args.user_name,
            args.first_name,
            args.last_name,
            passwd=passwd,
            uid=args.uid,
            gid=args.gid,
            home=home,
            shell=shell,
            ou=ou,
            domain=domain,
        )
    except CalledProcessError as error:
        return error.returncode

    master = DistinguishedName.for_master(domain)

    try:
        ldapadd(master, ldif)
    except CalledProcessError as error:
        return error.returncode

    return 0


def _modify(args: Namespace) -> int:
    """Modifies an LDAP user."""

    ou = args.ou or CONFIG.get("user", "ou")
    domain = args.domain or CONFIG.get("common", "domain")

    try:
        ldif = modify(
            args.user_name,
            first_name=args.first_name,
            last_name=args.last_name,
            passwd=args.passwd,
            uid=args.uid,
            gid=args.gid,
            home=args.home,
            shell=args.shell,
            ou=ou,
            domain=domain,
        )
    except CalledProcessError as error:
        return error.returncode

    master = DistinguishedName.for_master(domain)

    try:
        ldapmodify(master, ldif)
    except CalledProcessError as error:
        return error.returncode

    return 0


def _delete(args: Namespace) -> int:
    """Deletes the respective user."""

    ou = args.ou or CONFIG.get("user", "ou")
    domain = args.domain or CONFIG.get("common", "domain")
    dn = delete(args.user_name, ou=ou, domain=domain)
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

    if args.action == "delete":
        return _delete(args)

    LOGGER.error("No action specified.")
    return 3
