# -*- coding: latin-1 -*-
#
# Copyright 2009-2021 Ghent University
#
# This file is part of vsc-ldap,
# originally created by the HPC team of Ghent University (http://ugent.be/hpc/en),
# with support of Ghent University (http://ugent.be/hpc),
# the Flemish Supercomputer Centre (VSC) (https://www.vscentrum.be),
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
High-level tools for interacting with the LDAP for Virtual Organisations (VO).

@author: Andy Georges

The LdapVo class will bind to the LDAP server using LdapQuery, so
there is no need to do this manually.

If this code is extended, it should be Python 2.4 compatible until such time
as all machines where we might require LDAP accesss.
"""

# --------------------------------------------------------------------
from vsc.ldap import NoSuchVoError
from vsc.ldap.filters import CnFilter, MemberFilter
from vsc.ldap.utils import LdapEntity
from vsc.utils.fancylogger import getLogger


_log = getLogger(__name__)


class LdapVo(LdapEntity):
    """Representing a Virtual Organisation (VO) in the LDAP database.

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

    # Add at least one structural object class in a subclass.
    LDAP_OBJECT_CLASS_ATTRIBUTES = []

    def __init__(self, vo_id):
        """Initialisation.

        Will make the bind to the LDAP server.

        @type vo_id: string representing the ID of the VO, i.e., its cn in LDAP.

        @raise NoSuchVoError if the VO cannot be found.
        """
        super(LdapVo, self).__init__(vo_id)

    def get_ldap_info(self):
        """Retrieve the data from the LDAP to initially fill up the ldap_info field."""
        vo_ldap_info = self.ldap_query.vo_filter_search(CnFilter(self.vo_id))
        if len(vo_ldap_info) == 0:
            self.log.error("Could not find a group in the LDAP with the ID %s, raising NoSuchGroupError"
                           % (self.vo_id))
            raise NoSuchVoError(self.vo_id)

        return vo_ldap_info[0]  # there can be only one

    @staticmethod
    def get_for_member(user):
        """Look up the VO the given member belongs to.

        @type user: LdapUser instance for which we're looking up the VO.

        @returns: The LdapVo instance the user belongs to or None if
                  there is no such VO.
        """
        # gets all the attrributes provided by the LDAP server
        vos = user.ldap_query.vo_filter_search(MemberFilter(user.user_id))

        if len(vos) == 0:
            return None

        # there should be at most a single VO.
        if len(vos) > 1:
            _log.raiseException("Found multiple VOs for the given user (%s), vos = %s" % (user, vos))

        vo_info = vos[0]

        vo = LdapVo(vo_info['cn'])
        vo.ldap_info = vo_info

        return vo
