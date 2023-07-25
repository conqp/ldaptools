"""Common constants"""

from configparser import ConfigParser
from pathlib import Path


__all__ = ["CONFIG", "CONFIG_FILE"]


CONFIG = ConfigParser()
CONFIG_FILE = Path("/etc/ldaptools.conf")
