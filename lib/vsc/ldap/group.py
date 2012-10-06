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
High-level tools for interacting with the LDAP for groups.

The LdapGroup class will bind to the LDAP server using LdapQuery, so
there is no need to do this manually.

If this code is extended, it should be Python 2.4 compatible until such time
as all machines where we might require LDAP accesss.
"""

# --------------------------------------------------------------------
from vsc.ldap import NoSuchGroupError
from vsc.ldap.utils import LdapEntity, LdapQuery


class LdapGroup(LdapEntity):
    """Representing a group in the LDAP database.

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
    """

    def __init__(self, group_id):
        """Initialisation.

        Will make the bind to the LDAP server.

        @type group_id: string representing the ID of the group, i.e., its cn in LDAP.

        @raise NoSuchGroupError if the group cannot be found.
        """
        super(LdapGroup, self).__init__()
        self.group_id = group_id

    def get_ldap_info(self):
        """Retrieve the data from the LDAP to initially fill up the ldap_info field."""
        group_ldap_info = self.ldap_query.group_filter_search("cn=%s" % (self.group_id))
        if len(group_ldap_info) == 0:
            self.log.error("Could not find a group in the LDAP with the ID %s, raising NoSuchGroupError"
                              % (self.group_id))
            raise NoSuchGroupError(self.group_id)

        return group_ldap_info[0]  # there can be only one

    def modify_ldap(self, attributes):
        """Overiding the LdapEntity function.

        @type attributes: dictionary with the LDAP attributes.
        """
        self.ldap_query.group_modify(self.group_id, attributes)

    def add(self, ldap_attributes):
        """Adds a new group to the LDAP.

        Does two things:
            - effectively inserts the data into the LDAP database
            - fill in the attributes of the current instance, so we do not need to reload the data from the LDAP server
              if we access an field of this instance.

        @type ldap_attributes: dictionary with the LDAP field names and the associated values to insert.
        """
        ldap_attributes['objectClass'] = ['posixGroup', 'vscgroup']

        self.ldap_query.group_add(self.group_id, ldap_attributes)
        self.ldap_info = ldap_attributes

    @classmethod
    def lookup(cls, ldap_filter):
        """Lookup groups that match some filter criterium. Note that this will reaquire a second access later on.

        @ldap_filter: LdapFilter instance or string describing such a filter.

        @returns: list of cls instances that match the given filter criteria
        """
        ldap_query = LdapQuery()  # This should have been initialised earlier/elsewhere!

        groups = ldap_query.group_filter_search(ldap_filter, attributes=['cn'])

        return [cls(g['cn']) for g in groups if 'cn' in g]
