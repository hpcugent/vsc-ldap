# -*- coding: latin-1 -*-
#
# Copyright 2009-2016 Ghent University
#
# This file is part of vsc-ldap,
# originally created by the HPC team of Ghent University (http://ugent.be/hpc/en),
# with support of Ghent University (http://ugent.be/hpc),
# the Flemish Supercomputer Centre (VSC) (https://vscentrum.be/nl/en),
# the Hercules foundation (http://www.herculesstichting.be/in_English)
# and the Department of Economy, Science and Innovation (EWI) (http://www.ewi-vlaanderen.be/en).
#
# https://github.com/hpcugent/vsc-ldap
#
# vsc-ldap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation v2.
#
# vsc-ldap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with vsc-ldap.  If not, see <http://www.gnu.org/licenses/>.
#
"""
vsc.ldap package.

This package provides tools to connect and query an ldap server, and easily filter the results.

example usage:

>>> # create a configuration object
>>> from vsc.ldap.utils import LdapConfiguration
>>> from vsc.ldap.utils import LdapQuery
>>> uc = LdapConfiguration(url='ldap.eid.belgium.be', connection_dn='dc=eid,dc=belgium,dc=be')
>>> l = LdapQuery(uc)
>>> l.user_filter_search('sn=Smith')
[{}]


@author: Andy Georges
@author: Stijn De Weirdt
@author: Jens Timmerman
"""

#the vsc.ldap namespace is used in different folders allong the system
#so explicitly declare this is also the vsc namespace
import pkg_resources
pkg_resources.declare_namespace(__name__)


class NoSuchUserError(Exception):
    """If a user cannot be found in the LDAP."""
    def __init__(self, name):
        """Initialisation."""
        super(NoSuchUserError, self).__init__()
        self.name = name


class UserAlreadyExistsError(Exception):
    """If a user already is present in the LDAP, i.e., the dn already exists."""
    def __init__(self, name):
        """Initialisation."""
        super(UserAlreadyExistsError, self).__init__()
        self.name = name


class NoSuchVoError(Exception):
    """If a VO cannot be found in the LDAP."""
    def __init__(self, name):
        """Initialisation."""
        super(NoSuchVoError, self).__init__()
        self.name = name


class NoSuchGroupError(Exception):
    """If a group cannot be found in the LDAP."""
    def __init__(self, name):
        """Initialisation."""
        super(NoSuchGroupError, self).__init__()
        self.name = name


class NoSuchProjectError(Exception):
    """If a project cannot be found in the LDAP."""
    def __init__(self, name):
        """Initialisation."""
        super(NoSuchProjectError, self).__init__()
        self.name = name


class GroupAlreadyExistsError(Exception):
    """If a group is already present, i.e., the dn already exists."""
    def __init__(self, name):
        """Initialisation."""
        super(GroupAlreadyExistsError, self).__init__()
        self.name = name
