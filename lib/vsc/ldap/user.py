#!/usr/bin/env python
##
#
# Copyright 2012 Andy Georges
#
# This file is part of VSC-tools,
# originally created by the HPC team of the University of Ghent (http://ugent.be/hpc).
#
#
# http://github.com/hpcugent/VSC-tools
#
# VSC-tools is free software: you can redistribute it and/or modify
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
"""
High-level tools for interacting with the VSC LDAP for users.

The LdapUser class will bind to the LDAP server using LdapQuery, so
there is no need to do this manually.

If this code is extended, it should be Python 2.4 compatible until such time
as all machines where we might require LDAP accesss.

"""

# --------------------------------------------------------------------
from vsc.ldap import NoSuchUserError
from vsc.ldap.utils import LdapQuery, LdapEntity
from vsc.ldap.group import LdapGroup
from vsc.ldap.project import LdapProject
from vsc.ldap.vo import LdapVo


class LdapUser(LdapEntity):
    """Representing a user in the VSC LDAP database.

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
        - modify user attributes in the LDAP
    """

    def __init__(self, user_id):
        """Initialisation.

        Will make the bind to the LDAP server.

        @type user_id: string representing the ID of the user, i.e., his cn in LDAP.
        """
        super(LdapUser, self).__init__()
        self.user_id = user_id
        self.vo = None
        self.group = None  # the corresponding group for the user.
        self.projects = None  # projects the user participates in

    def get_ldap_info(self):
        """Retrieve the data from the LDAP to initially fill up the ldap_info field.
        """
        user_ldap_info = self.ldap_query.user_filter_search(filter="cn=%s" % (self.user_id))
        if len(user_ldap_info) == 0:
            self.logger.error("Could not find a user in the LDAP with the ID %s, raising NoSuchUserError"
                              % (self.user_id))
            raise NoSuchUserError(name=self.user_id)

        return user_ldap_info[0]

    def modify_ldap(self, attributes):
        """Overiding the LdapEntity function.

        @type attributes: dictionary with the LDAP attributes.
        """
        self.ldap_query.user_modify(self.user_id, attributes)

    def get_vo(self, reload=False):
        """Return the LdapVo instance of the VO a users belongs to.

        Assumes the VO has not changed. This can be overidden by providing the reload
        argument, otherwise, the cached version will be returned.

        @type reload: boolean that forces a reload of the VO.

        @returns: LdapVo instance or None if the user does not belong to a non-default VO.

        FIXME: This might need to move to a higher level, since the VOs are a VSC concept.
        """

        if not reload and self.vo:
            return self.vo

        self.vo = LdapVo.get_for_member(self)

        return self.vo

    def get_group(self, reload=False):
        """Return the LdapGroup that corresponds to this user.

        Assumes the group has not changed. This can be overridden by providing the reload argument, otherwise, the
        cached version will be returned.

        @type reload: boolean that forces a reload of the group.

        @returns: LdapGroup instance representing the group corresponding to the user.
        """

        if not reload and self.group:
            return self.group

        self.group = LdapGroup(self.user_id)

        return self.group

    def get_projects(self, ldap_filter=None, reload=False):
        """Return the projects thus user participates in.

        @type ldap_filter: LdapFilter object to apply to searching the projects.
        @type reload: boolean that forces a reload of the group.

        @returns: list of LdapProject
        """
        if not reload and not self.projects is None:
            return self.projects

        self.projects = LdapProject.get_for_member(self)

        return self.projects

    def add(self, ldap_attributes):
        """Adds a new user to the LDAP.

        Does two things:
            - effectively inserts the data into the LDAP database
            - fill in the attributes of the current instance, so we do not need to reload the data from the LDAP server
              if we access an field of this instance.

        @type ldap_attributes: dictionary with the LDAP field names and the associated values to insert.
        """
        ldap_attributes['objectClass'] = ['posixAccount', 'vscuser']

        self.ldap_query.user_add(self.user_id, ldap_attributes)
        self.ldap_info = ldap_attributes

    @classmethod
    def lookup(cls, ldap_filter):
        """Lookup users that match some filter criterium. Note that this will reaquire a second access later on.

        @ldap_filter: LdapFilter instance or string describing such a filter.

        @returns: list of cls instances that match the given filter criteria
        """
        ldap_query = LdapQuery()  # This should have been initialised earlier/elsewhere!

        users = ldap_query.user_filter_search(ldap_filter, attributes=['cn'])

        return [cls(u['cn']) for u in users if 'cn' in u]
