#! /usr/bin/env python3
#
#  ldaptools.py.
#
#  (C) 2018 Richard Neumann <mail at richard dash neumann period de>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
########################################################################
"""Tools to manage LDAP users."""

from contextlib import suppress
from grp import getgrall
from os import linesep
from pwd import getpwall
from random import choice
from string import ascii_letters, digits
from subprocess import CalledProcessError, check_output, run
from sys import exit as exit_, stderr
from tempfile import NamedTemporaryFile


SLAPPASSWD = '/usr/bin/slappasswd'
LDAPADD = '/usr/bin/ldapadd'
BASH = '/bin/bash'


class InvalidName(ValueError):
    """Indicates that an invalid name has been specified."""

    def __init__(self, name):
        """Sets the invalid name."""
        super().__init__(name)
        self.name = name

    def __str__(self):
        """Returns the error message."""
        return 'Invalid name: "{}".'.format(self.name)


class IdentifiersExhausted(Exception):
    """Indicates that the respective pool of identifiers is exhausted."""

    pass


def slappasswd(passwd):
    """Hashes a plain text password for LDIF."""

    return check_output((SLAPPASSWD, '-s', passwd)).decode()


def ldapadd(common_name, ldif):
    """Adds the respective LDIF file."""

    return run((LDAPADD, '-D', str(common_name), '-W', '-f', ldif))


def genpw(pool=ascii_letters+digits, length=8):
    """Generates a unique random password."""

    return ''.join(choice(pool) for _ in range(length))


def get_uid(min_=1000, max_=65544):
    """Returns a unique, unassigned user ID."""

    uids = tuple(user.pw_uid for user in getpwall())

    for uid in range(min_, max_):
        if uid not in uids:
            return uid

    raise IdentifiersExhausted('UIDs exhausted.')


def get_gid(min_=1000, max_=65543):
    """Returns a unique, unassigned group ID."""

    gids = tuple(group.gr_gid for group in getgrall())

    for gid in range(min_, max_):
        if gid not in gids:
            return gid

    raise IdentifiersExhausted('GIDs exhausted.')


def ldapuseradd(options):
    """useradd.

    Adds a new user.

Usage:
    ldapuseradd <dn> <user> [options]

Options:
    --passwd=<passwd>, -P   Sets the user's password.
    --uid=<uid>, -u         Sets the user's UID.
    --gid=<gid>, -g         Sets the user's GID.
    --shell=<shell>, -s     Sets the user's logn shell.
    --home=<home>, -d       Sets the user's home directory.
    --name=<name>, -n       Sets the user's full name.
    --title=<title>, -t     Sets the user's title.
    --phone=<phone>, -p     Sets the user's phone number.
    --mobile=<mobile>, -m   Sets the user's mobile phone number.
"""

    distinguished_name = options['<dn>']
    user = options['<user>']
    passwd = options['--passwd'] or genpw()
    uid = options['--uid'] or get_uid()
    gid = options['--gid'] or get_gid()
    shell = options['--shell'] or BASH
    home = options['--home']
    name = options['--name']
    title = options['--title']
    phone = options['--phone']
    mobile = options['--mobile']

    try:
        admin = LDAPAdmin.from_string(distinguished_name)
    except ValueError as value_error:
        print(value_error, file=stderr)
        return 2

    try:
        admin.useradd(
            user, passwd, uid=uid, gid=gid, shell=shell, home=home, name=name,
            title=title, phone=phone, mobile=mobile)
    except CalledProcessError as called_process_error:
        print(called_process_error.stderr.decode(), file=stderr)
        return 3

    return 0


class DistinguishedName:
    """Represents a distinguished name."""

    def __init__(self, *domain_components, common_name=None, uid=None,
                 organizational_unit=None):
        """Sets the respective components."""
        self.domain_components = domain_components
        self.common_name = common_name
        self.uid = uid
        self.organizational_unit = organizational_unit

    def __iter__(self):
        """Yields the respective entries."""
        if self.common_name is not None:
            yield ('cn', self.common_name)

        if self.uid is not None:
            yield ('uid', self.uid)

        if self.organizational_unit is not None:
            yield ('ou', self.organizational_unit)

        for domain_component in self.domain_components:
            yield ('dc', domain_component)

    def __str__(self):
        """Returns a string representation of the distinguished name."""
        return ','.join('{}={}'.format(key, value) for key, value in self)

    @classmethod
    def from_string(cls, string):
        """Creates a distinguished name from the provided string."""
        common_name = None
        uid = None
        organizational_unit = None
        domain_components = []

        for field in string.split(','):
            key, value = field.split('=')

            if key == 'cn':
                if common_name is None:
                    common_name = value
                else:
                    raise ValueError('Multiple common names specified.')
            elif key == 'uid':
                if uid is None:
                    uid = value
                else:
                    raise ValueError('Multiple UIDs specified.')
            elif key == 'ou':
                if organizational_unit is None:
                    organizational_unit = value
                else:
                    raise ValueError(
                        'Multiple organizational units specified.')
            elif key == 'dc':
                domain_components.append(value)
            else:
                raise ValueError(
                    'Invalid distinguished name component: {}.'.format(key))

        return cls(
            *domain_components, common_name=common_name, uid=uid,
            organizational_unit=organizational_unit)


class LDIF(dict):
    """LDIF configuration."""

    def __str__(self):
        """Returns the LDIF file as a string."""
        return linesep.join(self.lines)

    def __setitem__(self, key, value):
        """Sets the key to the respective value.
        If value is None, deletes the respective key.
        """
        if value is None:
            with suppress(KeyError):
                del self[key]
        else:
            super().__setitem__(key, value)

    @property
    def entries(self):
        """Yields all entries."""
        for key, value in self.items():
            if value is None:
                continue

            if isinstance(value, (tuple, list)):
                for item in value:
                    yield (key, item)
            else:
                yield (key, value)

    @property
    def lines(self):
        """Yields LDIF file lines."""
        for option, value in self.entries:
            yield '{}: {}'.format(option, value)


class LDIFUser(LDIF):
    """An LDIF user file."""

    def __init__(self, uid, organizational_unit, *domain_components):
        """Sets user ID, organizational unit, domain
        components and optional arguments.
        """
        super().__init__()
        self.distinguished_name = DistinguishedName(
            *domain_components, uid=uid,
            organizational_unit=organizational_unit)
        self.object_classes = [
            'top', 'person', 'organizationalPerson', 'inetOrgPerson',
            'posixAccount', 'shadowAccount']

    @property
    def distinguished_name(self):
        """Returns the distinguished name."""
        return self.get('dn')

    @distinguished_name.setter
    def distinguished_name(self, distinguished_name):
        """Sets the distinguished name."""
        self['dn'] = distinguished_name
        self.user_name = distinguished_name.uid

    @property
    def object_classes(self):
        """Returns the configured object classes."""
        return self.get('objectClass', ())

    @object_classes.setter
    def object_classes(self, object_classes):
        """Sets the object classes."""
        self['objectClass'] = object_classes

    @property
    def user_name(self):
        """Returns the user name."""
        return self.get('uid')

    @user_name.setter
    def user_name(self, user_name):
        """Sets the user name."""
        self['uid'] = user_name

    @property
    def common_name(self):
        """Returns the common name."""
        return self.get('cn')

    @common_name.setter
    def common_name(self, common_name):
        """Sets the common name."""
        self['cn'] = common_name

    @property
    def surname(self):
        """Returns the user's surname."""
        return self.get('sn')

    @surname.setter
    def surname(self, surname):
        """Sets the surname."""
        self['sn'] = surname

    @property
    def given_name(self):
        """Returns the given name."""
        return self.get('givenName')

    @given_name.setter
    def given_name(self, given_name):
        """Sets the given name."""
        self['givenName'] = given_name

    @property
    def title(self):
        """Returns the user's title."""
        return self.get('title')

    @title.setter
    def title(self, title):
        """Sets the user's title."""
        self['title'] = title

    @property
    def phone(self):
        """Returns the phone number."""
        return self.get('telephoneNumber')

    @phone.setter
    def phone(self, phone):
        """Sets the phone number."""
        self['telephoneNumber'] = phone

    @property
    def mobile(self):
        """Returns the mobile phone number."""
        return self.get('mobile')

    @mobile.setter
    def mobile(self, mobile):
        """Sets the mobile phone number."""
        self['mobile'] = mobile

    @property
    def address(self):
        """Returns the address."""
        return self.get('postalAddress')

    @address.setter
    def address(self, address):
        """Sets the address."""
        self['postalAddress'] = address

    @property
    def passwd(self):
        """Returns the users password hash."""
        return self.get('userPassword')

    @passwd.setter
    def passwd(self, passwd):
        """Sets the users password."""
        self['userPassword'] = slappasswd(passwd)

    @property
    def website(self):
        """Returns the user's website."""
        return self.get('labeledURI')

    @website.setter
    def website(self, website):
        """Sets the user's website."""
        self['labeledURI'] = website

    @property
    def shell(self):
        """Returns the user's shell."""
        return self.get('loginShell')

    @shell.setter
    def shell(self, shell):
        """Sets the user's shell."""
        self['loginShell'] = shell

    @property
    def uid(self):
        """Returns the UID."""
        return self.get('uidNumber')

    @uid.setter
    def uid(self, uid):
        """Sets the UID."""
        self['uidNumber'] = uid

    @property
    def gid(self):
        """Returns the group ID."""
        return self.get('gidNumber')

    @gid.setter
    def gid(self, gid):
        """Sets the group ID."""
        self['gidNumber'] = gid

    @property
    def home(self):
        """Returns the home directory."""
        return self.get('homeDirectory')

    @home.setter
    def home(self, home):
        """Sets the home directory."""
        self['homeDirectory'] = home

    @property
    def description(self):
        """Returns the description."""
        return self.get('description')

    @description.setter
    def description(self, description):
        """Sets the description."""
        self['description'] = description

    @property
    def name(self):
        """Returns the user's name."""
        return self.common_name

    @name.setter
    def name(self, name):
        """Sets the user's name."""
        try:
            given_name, *_, surname = name
        except ValueError:
            raise InvalidName(name)

        self.common_name = name
        self.surname = surname
        self.given_name = given_name


class LDAPAdmin(DistinguishedName):
    """Represents an LDAP admin."""

    def useradd(self, login_name, passwd, uid=None, gid=None, shell=BASH,
                home=None, name=None, title=None, phone=None, mobile=None):
        """Creates a new user."""

        user = LDIFUser(login_name, self.organizational_unit,
                        *self.domain_components)

        if passwd is None:
            passwd = genpw()

        user.passwd = passwd

        if uid is None:
            uid = get_uid()

        user.uid = uid

        if gid is None:
            gid = get_gid()

        user.gid = gid
        user.shell = shell

        if home is None:
            home = '/home/{}'.format(login_name)

        user.home = home

        if name is not None:
            user.name = name

        if title is not None:
            user.title = title

        if phone is not None:
            user.phone = phone

        if mobile is not None:
            user.mobile = mobile

        with NamedTemporaryFile(mode='w', suffix='.ldif') as ldif:
            ldif.write(str(user))
            ldif.flush()
            return ldapadd(self, ldif.name).check_returncode()


if __name__ == '__main__':
    try:
        from docopt import docopt
    except ImportError:
        print('docopt not installed. CLI not available.', file=stderr)
        exit_(4)

    exit_(ldapuseradd(docopt(__doc__)))
