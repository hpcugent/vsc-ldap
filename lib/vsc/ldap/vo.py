#!/usr/bin/env python
##
#
# Copyright 2012 Andy Georges
#
# This file is part of the tools originally by the HPC team of
# Ghent University (http://hpc.ugent.be).
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
"""
High-level tools for interacting with the HPC LDAP for Virtual Organisations (VO).

The LdapVo class will bind to the LDAP server using LdapQuery, so
there is no need to do this manually.

If this code is extended, it should be Python 2.4 compatible until such time
as all machines where we might require LDAP accesss.
"""

# --------------------------------------------------------------------
from vsc.ldap import NoSuchVoError
from vsc.ldap.utils import LdapEntity


class LdapVo(LdapEntity):
    """Representing a VO in the HPC LDAP database.

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

    def __init__(self, vo_id):
        """Initialisation.

        Will make the bind to the LDAP server.

        @type vo_id: string representing the ID of the VO, i.e., its cn in LDAP.

        @raise NoSuchVoError if the VO cannot be found.
        """
        super(LdapVo, self).__init__()
        self.vo_id = vo_id

    def get_ldap_info(self):
        """Retrieve the data from the LDAP to initially fill up the ldap_info field."""
        vo_ldap_info = self.ldap_query.vo_filter_search("cn=%s" % (self.vo_id))
        if len(vo_ldap_info) == 0:
            self.logger.error("Could not find a group in the LDAP with the ID %s, raising NoSuchGroupError" % (self.vo_id))
            raise NoSuchVoError(self.vo_id)

        return vo_ldap_info[0]  # there can be only one

    def add(self, ldap_attributes):
        """Adds a new vo to the HPC LDAP.

        Does two things:
            - effectively inserts the data into the LDAP database
            - fill in the attributes of the current instance, so we do not need to reload the data from the LDAP server
              if we access an field of this instance.

        @type ldap_attributes: dictionary with the LDAP field names and the associated values to insert.
        """
        # FIXME: Not sure about this. Should we include 'top'? Should we hardcode this or have the client code code it?
        ldap_attributes['objectClass'] = ['posixGroup', 'vscgroup']

        self.ldap_query.vo_add(self.vo_id, ldap_attributes)
        self.ldap_info = ldap_attributes

    @staticmethod
    def get_for_member(user):
        """Look up the VO the given member belongs to.

        @type user: LdapUser instance for which we're looking up the VO.

        @returns: The LdapVo instance the user belongs to or None if
                  there is no such VO.
        """

        vos = user.ldap_query.vo_filter_search("memberUid=%s" % user.user_id)  # gets all the attrributes provided by the LDAP server

        if len(vos) == 0:
            return None

        # there should be at most a single VO.
        if len(vos) > 1:
            raise Exception()

        vo_info = vos[0]

        vo = LdapVo(vo_info['cn'])
        vo.ldap_info = vo_info

        return vo
