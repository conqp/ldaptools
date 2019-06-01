#! /usr/bin/env python3

from distutils.core import setup

setup(
    name='ldaptools',
    version='latest',
    author='Richard Neumann',
    author_email='mail at richard dash neumann period de',
    packages=['ldaptools', 'ldaptools.cli'],
    scripts=['files/ldapuser', 'files/ldapgroup'],
    description='LDAP library with user and group management tools.')
