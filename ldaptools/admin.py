"""LDAP administration."""

from tempfile import NamedTemporaryFile

from ldaptools.ldif import DistinguishedName, LDIFUser
from ldaptools.misc import BASH, genpw, get_uid, get_gid, ldapadd

__all__ = ['LDAPAdmin']


class LDAPAdmin(DistinguishedName):
    """Represents an LDAP admin."""

    def useradd(self, login_name, passwd, uid=None, gid=None, shell=BASH,
                home=None, name=None, title=None, phone=None, mobile=None):
        """Creates a new user."""

        user = LDIFUser(login_name, self.organizational_unit,
                        *self.domain_components)

        if passwd is None:
            passwd = genpw()
            print('Generated password:', passwd, flush=True)

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
