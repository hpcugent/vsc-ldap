# -*- coding: latin-1 -*-
#
# Copyright 2009-2016 Ghent University
#
# This file is part of vsc-ldap,
# originally created by the HPC team of Ghent University (http://ugent.be/hpc/en),
# with support of Ghent University (http://ugent.be/hpc),
# the Flemish Supercomputer Centre (VSC) (https://vscentrum.be/nl/en),
# the Flemish Research Foundation (FWO) (http://www.fwo.be/en)
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
High-level tools for interacting with the LDAP for projects

@author: Andy Georges

The LdapProject class will bind to the LDAP server using LdapQuery, so
there is no need to do this manually.

If this code is extended, it should be Python 2.4 compatible until such time
as all machines where we might require LDAP accesss.
"""

# --------------------------------------------------------------------
from vsc.ldap import NoSuchProjectError
from vsc.ldap.utils import LdapEntity


class LdapProject(LdapEntity):
    """Representing a project in the LDAP database.

    Requires initialisation using a unique identification.

    It is important to realise that not all LDAP servers provide
    the same amount of information, some only provide a limited
    number of fields from the real (master) LDAP entry, since the
    machines they're running on typically need no more information
    and it is good practice keeping the provided amount of data
    to the minimum required for the the scripts to function in a
    proper manner.

    TL;DR Use a try/except block if you think the field might not
    be available.

    Provides the following functionality:
        - request information from the LDAP by accessing instance fields
        - add a user to the LDAP (if writing is allowed, responsibility of higher level)
        - modify project attributes in the LDAP
    """

    # Add at least one structural object class in a subclass.
    LDAP_OBJECT_CLASS_ATTRIBUTES = []

    def __init__(self, project_id):
        """Initialisation.

        Will make the bind to the LDAP server.

        @type project_id: string representing the ID of the project, i.e., its cn in LDAP.

        @raise NoSuchProjectError if the project cannot be found.
        """
        super(LdapProject, self).__init__(self.LDAP_OBJECT_CLASS_ATTRIBUTES)
        self.project_id = project_id

    def get_ldap_info(self):
        """Retrieve the data from the LDAP to initially fill up the ldap_info field."""
        project_ldap_info = self.ldap_query.project_filter_search("cn=%s" % (self.project_id))
        if len(project_ldap_info) == 0:
            self.log.error("Could not find a project in the LDAP with the ID %s, raising NoSuchGroupError"
                           % (self.project_id))
            raise NoSuchProjectError(self.project_id)

        return project_ldap_info[0]  # there can be only one

    def add(self, ldap_attributes):
        """Adds a new project to the LDAP.

        Does two things:
            - effectively inserts the data into the LDAP database
            - fill in the attributes of the current instance, so we do not need to reload the data from the LDAP server
              if we access an field of this instance.

        @type ldap_attributes: dictionary with the LDAP field names and the associated values to insert.
        """
        ldap_attributes['objectClass'] = self.LDAP_OBJECT_CLASS_ATTRIBUTES

        self.ldap_query.project_add(self.project_id, ldap_attributes)
        self.ldap_info = ldap_attributes

    @staticmethod
    def get_for_member(user):
        """Look up the projects the given member is participating in.

        @type user: LdapUser instance for which we're looking up the projects.

        @returns: A list of all the projects the given user is participating in. This list is empty if there are no such
        projects for the given user.
        """

        # get all the projects in the LDAP
        projects_info = user.ldap_query.projects_filter_search("memberUid=%s" % user.user_id)

        projects = []
        for p_info in projects_info:
            p = LdapProject(p_info['cn'])
            p.ldap_info = p_info
            projects.append(p)

        return projects
