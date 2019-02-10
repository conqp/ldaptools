"""Common constants"""

__all__ = ['SLAPPASSWD', 'LDAPADD', 'BASH', 'HOME', 'USER_CLASSES', 'USER_OU']


SLAPPASSWD = '/usr/bin/slappasswd'
LDAPADD = '/usr/bin/ldapadd'
BASH = '/bin/bash'
GROUP_CLASSES = ('top', 'posixGroup')
GROUP_OU = 'Group'
HOME = '/home/{}'
USER_CLASSES = (
    'top',
    'person',
    'organizationalPerson',
    'inetOrgPerson',
    'posixAccount',
    'shadowAccount')
USER_OU = 'People'
