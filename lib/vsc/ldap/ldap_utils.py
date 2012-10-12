#!/usr/bin/env python
##
#
# Copyright 2012 Stijn De Weirdt
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
Low-level LDAP tools, wrapping the python-ldap functions.

For third party docs, see http://www.python-ldap.org/docs.shtml
"""
import datetime
import ldap
import ldap.schema

from ldapurl import LDAPUrl

import vsc.fancylogger as fancylogger
from vsc.dateandtime import Local, utc

LDAP_DATETIME_TIMEFORMAT = "%Y%m%d%H%M%SZ"


class LdapConfiguration(object):
    """Represents some LDAP configuration.

    This is an abstract class and should be implemented elsewhere.
    """
    def __init__(self):
        self.url = None
        self.password = None
        self.connection_dn = None
        self.validation_method = None
        self.check_server_certificate = False

        self.log = fancylogger.getLogger(self.__class__.__name__)


class LdapConnection(object):
    """Represents a connection to an LDAP server.

    - Offers a set of convenience functions for querying and updating the server.
    - Requires a Configuration object that can be queried for providing details about the connection (server, port, ...)

    Implemented low-level funcitonality:
        - connect
        - search (synchronously, asynchronously)
        - modify
        - add
    """
    def __init__(self, configuration):
        """Initialisation. Not done lazily.

        @type configuration: vsc.ldap.utils.Configuration subclass instance, implementing the actual functions to request
                             information.
        """
        self.log = fancylogger.getLogger(name=self.__class__.__name__)
        self.configuration = configuration
        self.ldap_connection = None

    def connect(self):
        """Connect to the LDAP server provided by the configuration.

        @raise ldap.LDAPError if the connection cannot be established
        """
        if self.configuration.check_server_certificate:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, self.configuration.validation_method)

        ldap_url = self.configuration.url
        try:
            self.ldap_connection = ldap.initialize(ldap_url)
        except ldap.LDAPError, err:
            self.log.raiseException("Failed to connect to the LDAP server at %s" % (ldap_url), err)

        ## generate ldapurl obj after succesfull connect
        self.ldap_url = LDAPUrl(ldapUrl=ldap_url)

    def bind(self):
        """Bind to the LDAP service.

        @raise LDAPError: if we cannot bind to the LDAP service.
        """

        if not self.ldap_connection:
            try:
                self.connect()
            except ldap.LDAPError, err:
                self.log.raiseException("Binding to LDAP failed - no connection.", err)

        password = self.configuration.password
        dn = self.configuration.connection_dn

        try:
            res = self.ldap_connection.simple_bind_s(dn, password)
            self.log.debug("Binding to LDAP with dn %s resulted in %s" % (dn, res))
        except ldap.LDAPError, err:
            self.log.raiseException("Binding to LDAP failed", err)

        ## update url after succesful bind
        ## WARNING self.ldap_url.unparse() will show the password. don't use it in logging !!
        self.ldap_url.who = dn
        self.ldap_url.cred = password

    def search(self, ldap_filter, base, attrs=None, sync=True):
        """Search the LDAP entries for the given attributes.

        @return: list of dictionaries with the requested attributes as keys

        @raise LDAPError: if the service cannot be bound.
        """
        ## always rebind as in perl version?
        if self.ldap_connection is None:
            self.bind()

        if sync:
            res = self.search_sync(ldap_filter, base, attrs)
        else:
            res = self.search_async_timeout(ldap_filter, base, attrs)

        self.log.debug("Ldap search returned base %s, ldap_filter %s, attrs %s: %s" % (base, ldap_filter, attrs, res))

        ## refine result result=[('dn',{})[,()]] into [{}[,{}]]
        endres = [t[1] for t in res]
        self.log.debug("Result reformed into %s" % (endres))

        return endres

    def search_sync(self, ldap_filter, base, attributes=None):
        """Perform a synchronous search.

        @return: list of dictionaries with the requested attributes as keys

        @raise LDAPError: when the search borks.
        """
        if self.ldap_connection is None:
            self.bind()

        ## ldap_filter can also be an LdapFilter instance
        ldap_filter = "%s" % ldap_filter

        try:
            res = self.ldap_connection.search_s(base, ldap.SCOPE_SUBTREE, ldap_filter, attributes)
        except ldap.LDAPError, err:
            self.log.raiseException("Ldap sync search failed: base %s, ldap_filter %s, attributes %s"
                           % (base, ldap_filter, attributes), err)

        return res

    def search_async_timeout(self, ldap_filter, base, attributes=None, timeout=10):
        """Perform an asynchronous search with a predefined timeout.

        Default timeout value = 10s.

        @return: list of dictionaries with the requested attributes as keys

        @raise LDAPError: when the search borks.
        """
        if self.ldap_connection is None:
            self.bind()
        attrs_only = False

        ## filter can also be LdapFilter instance
        ldap_filter = "%s" % ldap_filter

        try:
            res = self.ldap_connection.search_st(base, ldap.SCOPE_SUBTREE, ldap_filter, attributes, attrs_only, timeout)
        except ldap.LDAPError, err:
            self.log.raiseException("Ldap async timeout search failed: base %s, ldap_filter %s, attributes %s: %s"
                           % (base, ldap_filter, attributes), err)

        return res

    def modify(self, dn, attribute, value):
        """
        Change the value for the given attribute.

        @type dn: distinguished name of the entry to modify.

        @raise LDAPError: if the update borks.
        """
        if self.ldap_connection is None:
            self.bind()

        mod_attrs = [(ldap.MOD_REPLACE, attribute, value)]
        try:
            self.ldap_connection.modify_s(dn, mod_attrs)
        except ldap.LDAPError, err:
            self.log.raiseException("Ldap update failed: dn %s, attribute %s, value %s: %s" % (dn, attribute, value), err)

    def modify_attributes(self, dn, changes):
        """Modify one or more attributes.

        @type changes: list of tuples (action, ldap key, value) resulting from a ldap.modlist.modifyModlist.

        @raise LDAPError: if the update borks.
        """
        if self.ldap_connection is None:
            self.bind()

        try:
            self.ldap_connection.modify_s(dn, changes)
        except ldap.LDAPError, err:
            self.log.raiseException("Ldap update failed: dn %s, changes %s" % (dn, changes), err)

    def add(self, dn, attributes):
        """Add an entry for the given distinguished name with the given attributes and their corresponding values.

        @type dn: distinguished name of the entry to modify.
        @type attributes: list of tuples (ldap key, value) of data to add to the entry

        @raise LDAPError: if the add borks.
        """
        if self.ldap_connection is None:
            self.bind()

        changes = [(k, [v]) for (k, v) in attributes if not type(v) == list]
        changes.extend([(k, v) for (k, v) in attributes if type(v) == list])
        self.log.info("Adding for dn=%s with changes = %s" % (dn, changes))

        try:
            self.ldap_connection.add_s(dn, changes)
        except ldap.LDAPError, err:
            self.log.raiseException("Ldap add failed: dn %s, changes %s [%s]", (dn, changes), err)


def convertTimestamp(timestamp=None):
    """Convert a timestamp, yielding a string and a datetime.datetime instance.

    @type timestamp: either a string or a datetime.datetime instance. Default value is None, in which case the
                     local time is returned.

    @returns: tuple with the timestamp as a
                - LDAP formatted timestamp on GMT in the yyyymmddhhmmssZ format
                - A datetime.datetime instance representing the timestamp
    """
    if timestamp is None:
        timestamp = datetime.datetime.today()

    if isinstance(timestamp, datetime.datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=Local)
        return (timestamp, timestamp.astimezone(utc).strftime(LDAP_DATETIME_TIMEFORMAT))

    elif isinstance(timestamp, str):
        tmp = datetime.datetime.strptime(timestamp, LDAP_DATETIME_TIMEFORMAT)
        return (tmp.replace(tzinfo=utc).astimezone(Local), timestamp)
