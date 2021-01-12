#! /usr/bin/env python3
"""Installation script."""

from setuptools import setup

setup(
    name='ldaptools',
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    author='Richard Neumann',
    author_email='mail@richard-neumann.de',
    python_requires='>=3.8',
    packages=['ldaptools', 'ldaptools.cli'],
    entry_points={
        'console_scripts': [
            'ldapgroup = ldaptools.cli.ldapgroup:main',
            'ldapuser = ldaptools.cli.ldapuser:main'
        ],
    },
    url='https://github.com/conqp/ldaptools',
    license='GPLv3',
    description='LDAP library with user and group management tools.',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    keywords='ldap python bundings tools'
)
