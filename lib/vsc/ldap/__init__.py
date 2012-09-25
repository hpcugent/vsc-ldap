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
"""vsc.ldap package.

Provides:
- Errors raised by the VSC LDAP package
"""


class NoSuchUserError(Exception):
    def __init__(self, name):
        super(NoSuchUserError, self).__init__()
        self.name = name


class UserAlreadyExistsError(Exception):
    def __init__(self, name):
        super(UserAlreadyExistsError, self).__init__()
        self.name = name


class NoSuchVoError(Exception):
    def __init__(self, name):
        super(NoSuchVoError, self).__init__()
        self.name = name


class NoSuchGroupError(Exception):
    def __init__(self, name):
        super(NoSuchGroupError, self).__init__()
        self.name = name


class NoSuchProjectError(Exception):
    def __init__(self, name):
        super(NoSuchProjectError, self).__init__()
        self.name = name


class GroupAlreadyExistsError(Exception):
    def __init__(self, name):
        super(GroupAlreadyExistsError, self).__init__()
        self.name = name
