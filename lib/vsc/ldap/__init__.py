#!/usr/bin/env python
##
#
# Copyright 2012 Andy Georges
#
# This file is part of the tools originally by the HPC team of
# Ghent University (http://ugent.be/hpc).
#
# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation v2.
#
# VSC-tools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with VSC-tools. If not, see <http://www.gnu.org/licenses/>.
##
"""vsc.ldap package.

Provides:
- Errors raised by the VSC LDAP package
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
