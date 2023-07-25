"""User and group management."""

from typing import Iterator

from ldaptools.config import CONFIG
from ldaptools.functions import classes, get_uid, get_gid, get_pwhash
from ldaptools.ldif import DistinguishedName, LDIF, LDIFEntry


__all__ = ["create", "modify", "delete"]


def get_cn(first_name: str, last_name: str) -> str | None:
    """Returns the respective common name."""

    if first_name is None and last_name is None:
        return None

    if first_name is not None and last_name is not None:
        return " ".join((first_name, last_name))

    raise ValueError("Must specify both, first and last name or neither.")


@LDIF.constructor
def create(
    name: str,
    first_name: str,
    last_name: str,
    *,
    passwd: str | None = None,
    pwhash: str | None = None,
    uid: int | None = None,
    gid: int | None = None,
    home: str | None = None,
    shell: str | None = None,
    ou: str | None = None,
    domain: str | None = None,
) -> Iterator[LDIFEntry]:
    """Creates an LDIF representing a new user."""

    yield LDIFEntry(
        "dn",
        DistinguishedName.for_user(
            name,
            CONFIG.get("common", "domain") if domain is None else domain,
            ou=CONFIG.get("user", "ou") if ou is None else ou,
        ),
    )

    for clas in classes(CONFIG.get("user", "classes", fallback=None)):
        yield LDIFEntry("objectClass", clas)

    yield LDIFEntry("uid", name)
    yield LDIFEntry("cn", " ".join((first_name, last_name)))
    yield LDIFEntry("sn", last_name)
    yield LDIFEntry("givenName", first_name)
    yield LDIFEntry("userPassword", get_pwhash(passwd=passwd, pwhash=pwhash))
    yield LDIFEntry(
        "loginShell", CONFIG.get("user", "shell") if shell is None else shell
    )
    yield LDIFEntry("uidNumber", get_uid() if uid is None else uid)
    yield LDIFEntry("gidNumber", get_gid() if gid is None else gid)
    yield LDIFEntry(
        "homeDirectory",
        (CONFIG.get("user", "home") if home is None else home).format(name),
    )


@LDIF.constructor
def modify(
    name: str,
    *,
    new_name: str | None = None,
    uid: int | None = None,
    gid: int | None = None,
    first_name: str | None = None,
    last_name: str | None = None,
    passwd: str | None = None,
    pwhash: str | None = None,
    home: str | None = None,
    shell: str | None = None,
    ou: str | None = None,
    domain: str | None = None,
) -> Iterator[LDIFEntry]:
    """Creates an LDIF to modify a user."""

    yield LDIFEntry(
        "dn",
        DistinguishedName.for_user(
            name,
            CONFIG.get("common", "domain") if domain is None else domain,
            ou=CONFIG.get("user", "ou") if ou is None else ou,
        ),
    )
    yield LDIFEntry("changetype", "modify")

    if new_name is not None:
        yield LDIFEntry("replace", "uid")
        yield LDIFEntry("uid", new_name)

    if cn := get_cn(first_name, last_name):
        yield LDIFEntry("replace", "cn")
        yield LDIFEntry("cn", cn)

    if last_name is not None:
        yield LDIFEntry("replace", "sn")
        yield LDIFEntry("sn", last_name)

    if first_name is not None:
        yield LDIFEntry("replace", "givenName")
        yield LDIFEntry("givenName", first_name)

    if pwhash is None and passwd is None:
        pwhash = None
    else:
        pwhash = get_pwhash(passwd=passwd, pwhash=pwhash)

    if pwhash is not None:
        yield LDIFEntry("replace", "userPassword")
        yield LDIFEntry("userPassword", pwhash)

    if shell is not None:
        yield LDIFEntry("replace", "loginShell")
        yield LDIFEntry("loginShell", shell)

    if uid is not None:
        yield LDIFEntry("replace", "uidNumber")
        yield LDIFEntry("uidNumber", uid)

    if gid is not None:
        yield LDIFEntry("replace", "gidNumber")
        yield LDIFEntry("gidNumber", gid)

    if home is not None:
        yield LDIFEntry("replace", "homeDirectory")
        yield LDIFEntry("homeDirectory", home)


def delete(
    name: str, *, ou: str | None = None, domain: str | None = None
) -> DistinguishedName:
    """Creates an LDIF to delete a user."""

    return DistinguishedName.for_user(
        name,
        CONFIG.get("common", "domain") if domain is None else domain,
        ou=CONFIG.get("user", "ou") if ou is None else ou,
    )
