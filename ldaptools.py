"""Tools to manage LDAP users."""

from os import linesep


SLAPPASSWD = '/usr/bin/slappasswd'


class InvalidName(ValueError):
    """Indicates that an invalid name has been specified."""

    def __init__(self, name):
        """Sets the invalid name."""
        super().__init__(name)
        self.name = name


def ldap_hash(passwd):
    """Hashes a plain text password for LDIF."""

    return check_output((SLAPPASSWD, '-s', passwd)).decode()


class DistinguishedName:
    """Represents a distinguished name."""

    def __init__(self, uid, organizational_unit, *domain_components):
        """Sets the respective components."""
        self.uid = uid
        self.organizational_unit = organizational_unit
        self.domain_components = domain_components

    def __iter__(self):
        """Yields the respective entries."""
        yield ('uid', self.uid)
        yield ('ou', self.organizational_unit)

        for domain_component in self.domain_components:
            yield ('dc', domain_component)

    def __str__(self):
        """Returns a string representation of the distinguished name."""
        return ','.join(self)


class LDIF(dict):
    """LDIF configuration."""

    def __str__(self):
        """Returns the LDIF file as a string."""
        return linesep.join(self.lines)

    @property
    def entries(self):
        """Yields all entries."""
        for key, value in self.items():
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

    def __init__(self, uid, organizational_unit, *domain_components, **kwargs):
        """Sets user ID, organizational unit, domain
        components and optional arguments.
        """
        super().__init__(kwargs)
        self.distinguished_name = DistinguishedName(
            uid, organizational_unit, *domain_components)

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
        self['userPassword'] = ldap_hash(passwd)

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
