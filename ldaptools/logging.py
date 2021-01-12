"""Logging facility."""

from logging import getLogger
from sys import argv


__all__ = ['LOG_FORMAT', 'LOGGER']


LOG_FORMAT = '[%(levelname)s] %(name)s: %(message)s'
LOGGER = getLogger(argv[0])
