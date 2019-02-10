"""Common constants"""

from configparser import ConfigParser


__all__ = ['CONFIG']


CONFIG = ConfigParser()
CONFIG.read('/etc/ldaptools.conf')
