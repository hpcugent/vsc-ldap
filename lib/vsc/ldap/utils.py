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
"""Convenience classes for using the LDAP.

@author: Andy Georges
@author: Stijn De Weirdt
@author: Wouter Depypere
"""
import logging
from future.utils import with_metaclass

import ldap
import ldap.modlist
import ldap.schema

from ldapurl import LDAPUrl

from vsc.ldap.filters import CnFilter, LdapFilter, MemberFilter
from vsc.ldap import NoSuchUserError, NoSuchGroupError, NoSuchProjectError
from vsc.utils.missing import TryOrFail
from vsc.utils.patterns import Singleton

EMPTY_GECOS_DURING_MODIFY = "EMPTYGECOSDURINGMODIFY"


class LdapConfiguration(object):
    """Represents some LDAP configuration.

    @param url: url to ldap server (default None)
    @param password: ldap password (default None)
    @param connection_dn: ldap dn as a string, e.g., 'dc=eid,dc=belgium,dc=be' (default None
    @param validation_method: constant from ldap, (default ldap.OPT_X_TLS_DEMAND )
    see http://www.python-ldap.org/doc/html/ldap.html
    @param check_certificate: bool, check the server certificate? (default False)
    """
    def __init__(self, url=None, password=None, connection_dn=None, validation_method=None, check_certificate=False):
        self.url = url
        self.password = password
        self.connection_dn = connection_dn
        self.validation_method = validation_method
        self.check_server_certificate = lambda: check_certificate

    def tls_settings(self, url):
        """
        Set up the LDAP for a TLS connection.
        """
        if url.startswith("ldaps"):
            ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, True)
            ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        else:
            logging.warning("Not using TLS for LDAP connection, consider upgrading.")


class SchemaConfiguration(LdapConfiguration):
    """Represents an LDAP configuration with some extra schema-related information."""

    def __init__(self):
        super(SchemaConfiguration, self).__init__()

        self.user_dn_base = None
        self.group_dn_base = None
        self.project_dn_base = None
        self.vo_dn_base = None

        self.user_multi_value_attributes = None
        self.group_multi_value_attributes = None
        self.project_multi_value_attributes = None
        self.vo_multi_value_attributes = None


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

        @type configuration: vsc.ldap.utils.Configuration subclass instance,
                             implementing the actual functions to request information.
        """
        self.configuration = configuration
        self.ldap_connection = None

    @TryOrFail(3, (ldap.LDAPError,), 10)
    def connect(self):
        """Connect to the LDAP server provided by the configuration.

        @raise ldap.LDAPError if the connection cannot be established
        """
        # set security options through the configuration

        # we connect on a first listed, first tried basis
        for url in self.configuration.urls:
            try:
                self.configuration.tls_settings(url)
                self.ldap_connection = ldap.initialize(url)
                self.ldap_url = LDAPUrl(ldapUrl=url)
                break
            except ldap.LDAPError:
                logging.exception("Failed to connect to the LDAP server at %s", url)
                raise

    @TryOrFail(3, (ldap.LDAPError,), 10)
    def bind(self):
        """Bind to the LDAP service.

        @raise LDAPError: if we cannot bind to the LDAP service.
        """

        if not self.ldap_connection:
            try:
                self.connect()
            except ldap.LDAPError:
                logging.exception("Binding to LDAP failed - no connection.")
                raise

        password = self.configuration.password
        dn = self.configuration.connection_dn

        try:
            res = self.ldap_connection.simple_bind_s(dn, password)
            logging.debug("Binding to LDAP with dn %s resulted in %s", dn, res)
        except ldap.LDAPError:
            logging.exception("Binding to LDAP failed")
            raise

        # update url after succesful bind
        # WARNING self.ldap_url.unparse() will show the password. don't use it in logging !!
        self.ldap_url.who = dn
        self.ldap_url.cred = password

    def search(self, ldap_filter, base, attrs=None, sync=True):
        """Search the LDAP entries for the given attributes.

        @return: list of dictionaries with the requested attributes as keys
        """
        # always rebind as in perl version?
        if self.ldap_connection is None:
            self.bind()

        if sync:
            res = self.search_sync(ldap_filter, base, attrs)
        else:
            res = self.search_async_timeout(ldap_filter, base, attrs)

        logging.debug("Ldap search returned base %s, ldap_filter %s, attrs %s: %s", base, ldap_filter, attrs, res)

        # refine result result=[('dn',{})[,()]] into [{}[,{}]]
        endres = [t[1] for t in res]
        logging.debug("Result reformed into %s", endres)

        return endres

    def search_sync(self, ldap_filter, base, attributes=None):
        """Perform a synchronous search.

        @return: list of dictionaries with the requested attributes as keys

        @raise LDAPError: when the search borks.
        """
        if self.ldap_connection is None:
            self.bind()

        # ldap_filter can also be an LdapFilter instance
        ldap_filter = "%s" % ldap_filter

        try:
            res = self.ldap_connection.search_s(base, ldap.SCOPE_SUBTREE, ldap_filter, attributes)
        except ldap.LDAPError:
            logging.exception("Ldap sync search failed: base %s, ldap_filter %s, attributes %s",
                base, ldap_filter, attributes)
            raise

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

        # filter can also be LdapFilter instance
        ldap_filter = "%s" % ldap_filter

        try:
            res = self.ldap_connection.search_st(base, ldap.SCOPE_SUBTREE, ldap_filter, attributes, attrs_only, timeout)
        except ldap.LDAPError:
            logging.exception("Ldap async timeout search failed: base %s, ldap_filter %s, attributes %s:",
                base, ldap_filter, attributes)
            raise

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
        except ldap.LDAPError:
            logging.exception("Ldap update failed: dn %s, attribute %s, value %s", dn, attribute, value)
            raise

    def modify_attributes(self, dn, changes):
        """Modify one or more attributes.

        @type changes: list of tuples (action, ldap key, value) resulting from a ldap.modlist.modifyModlist.

        @raise LDAPError: if the update borks.
        """
        if self.ldap_connection is None:
            self.bind()

        try:
            self.ldap_connection.modify_s(dn, changes)
        except ldap.LDAPError:
            logging.exception("Ldap update failed: dn %s, changes %s", dn, changes)
            raise

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
        logging.info("Adding for dn=%s with changes = %s", dn, changes)

        try:
            self.ldap_connection.add_s(dn, changes)
        except ldap.LDAPError:
            logging.exception("Ldap add failed: dn %s, changes %s [%s]", dn, changes, attributes)
            raise


class LdapQuery(with_metaclass(Singleton)):
    """Singleton class to interact with the LDAP server.

    This level is LDAP-schema aware. It knows about the dn for people, groups and projects.

    Allows searching for
        - users
        - groups
        - projects

    If distinct group types that are required that are identified, e.g., by specific names, subclass LdapQuery
    and/or use the post_filter arguments.
    """

    def __init__(self, configuration):
        """
        Initalisation.

        @type configuration: a SchemaConfiguration instance.

        If you initialise using None as the configuration, this will not fail
        if the singleton has already been created.
        """
        self.configuration = configuration
        self.ldap = LdapConnection(configuration)

        self.ldap.connect()
        self.ldap.bind()

        self.schema = {}

    def _filter_search(self, base, multi_value_attributes, ldap_filter, attributes, post_filter):
        entries = self.ldap.search(ldap_filter, base, attributes)
        results = [self.__delist_ldap_return_value(e, multi_value_attributes, attributes) for e in entries]
        if post_filter:
            (attribute, regex) = post_filter
            results = [r for r in results if regex.match(r[attribute])]

        logging.debug("_filter_search finds %d results", len(results))
        return results

    def group_filter_search(self, ldap_filter, attributes=None, post_filter=None):
        """Perform an LDAP lookup in the group tree, based on the given filter.

        @type ldap_filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all retrieved attributes.
        @type post_filter: (attribute name, compiled regex), allows filtering the results
                           based on the specified attribute matching the givenregex. Note
                           that the attribute is matched, not searched.

        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if not self.ldap:
            logging.error("LDAP search request (group_filter_search) failed: ldap not initialised")
            raise ldap.OTHER()

        # for groups, we use the following base
        logging.debug("group_filter_search: ldap_filter = %s, requested attributes = %s", ldap_filter, attributes)

        return self._filter_search(self.configuration.group_dn_base,
                                   self.configuration.group_multi_value_attributes,
                                   ldap_filter,
                                   attributes,
                                   post_filter)

    def group_search(self, cn, member_uid, attributes=None):
        """Perform an LDAP lookup in the group tree, looking for the entry with given cn and memberUid.

        @type cn: string representing the desired common name in the LDAP database
        @type member_uid: string representing the member's user id in the LDAP database?
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all the retrieved attributes

        @returns: the matching LDAP entry as a dictionary, limited to the requested attributes.
        """
        logging.debug("group_search: cn = %s, member_uid = %s, requested attributes = %s",
            cn, member_uid, attributes)
        cn_filter = CnFilter(cn)
        member_filter = MemberFilter(member_uid)
        result = self.group_filter_search(cn_filter & member_filter, attributes)
        logging.debug("group_search for %s, %s yields %s", cn, member_uid, result)
        if result is not None and len(result) > 0:
            return result[0]
        else:
            logging.debug("group_search returning None")
            return None

    def project_filter_search(self, ldap_filter, attributes=None, post_filter=None):
        """Perform an LDAP lookup in the projects tree, based on the given filter.

        @type ldap_filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all retrieved attributes
        @type post_filter: (attribute name, compiled regex), allows filtering the results
                           based on the specified attribute matching the givenregex. Note
                           that the attribute is matched, not searched.

        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if not self.ldap:
            logging.error("LDAP search request (user_filter_search) failed: ldap not initialised")
            raise ldap.OTHER()

        return self._filter_search(self.configuration.project_dn_base,
                                   self.configuration.project_multi_value_attributes,
                                   ldap_filter,
                                   attributes,
                                   post_filter)

    def vo_filter_search(self, ldap_filter, attributes=None, post_filter=None):
        """Perform an LDAP lookup in the VO tree, based on the given filter.

        @type ldap_filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all retrieved attributes
        @type post_filter: (attribute name, compiled regex), allows filtering the results
                           based on the specified attribute matching the givenregex. Note
                           that the attribute is matched, not searched.

        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if not self.ldap:
            logging.error("LDAP search request (user_filter_search) failed: ldap not initialised")
            raise ldap.OTHER()

        return self._filter_search(self.configuration.vo_dn_base,
                                   self.configuration.vo_multi_value_attributes,
                                   ldap_filter,
                                   attributes,
                                   post_filter)

    def user_filter_search(self, ldap_filter, attributes=None, post_filter=None):
        """Perform an LDAP lookup in the user tree, based on the given filter.

        @type filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all retrieved attributes
        @type post_filter: (attribute name, compiled regex), allows filtering the results
                           based on the specified attribute matching the givenregex. Note
                           that the attribute is matched, not searched.

        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if not self.ldap:
            logging.error("LDAP search request (user_filter_search) failed: ldap not initialised")
            raise ldap.OTHER()

        # For users, we use the following base:
        logging.debug("user_filter_search: filter = %s, requested attributes = %s", ldap_filter, attributes)
        return self._filter_search(self.configuration.user_dn_base,
                                   self.configuration.user_multi_value_attributes,
                                   ldap_filter,
                                   attributes,
                                   post_filter)

    def user_search(self, user_id, institute, attributes=None):
        """Perform an LDAP search for the given user and institute.

        Note that both user_id and institute are mandatory here. If this is
        not what you want, you should instead use user_filter_search.

        @type user_id: string representing the user login in the given institute
        @type institute: string representing the institute
        @type attributes: list of string describing LDAP attributes. If this is
                           None (default) then all attributes are returned.

        @returns: a dictionary, with the values for the requested attributes for the given user
        """
        login_filter = LdapFilter("instituteLogin=%s" % (user_id))
        institute_filter = LdapFilter("institute=%s" % (institute))

        result = self.user_filter_search(login_filter & institute_filter, attributes)
        logging.debug("user_search for %s, %s yields %s", user_id, institute, result)
        if result is not None and len(result) > 0:
            return result[0]
        else:
            logging.debug("user_search returning None")
            return None

    def __delist_ldap_return_value(self, entry, list_attributes=None, attributes=None):
        """Get sensible values, i.e., not lists in the LDAP returned values
        if they're not needed.

        Note that a user can have e.g., multiple public keys, so we're keeping
        that as a list. Such attributes should be specified in the list_attributes

        @type entry: LDAP result entry as a dictionary
        @type list_attributes
        @type attributes: attribute names we wish to retain
        """
        kvs = [(k, v[0]) for (k, v) in entry.items()
               if (list_attributes is None or k not in list_attributes)
               and (attributes is None or k in attributes)]
        # we do want to get all the attributes that provide multiple items
        for a in list_attributes:
            if (attributes is None or a in attributes) and a in entry:
                kvs.append((a, entry[a]))
        return dict(kvs)

    def __modify(self, current, dn, attributes):
        """Actually make the modification."""
        current_ = {}
        for key in attributes.keys():
            current_[key] = current.get(key, [])
            if current_[key] is '':
                logging.warning("Replacing empty string for key %s with %s before making modlist for dn %s",
                    key, EMPTY_GECOS_DURING_MODIFY, dn)
                current_[key] = EMPTY_GECOS_DURING_MODIFY  # hack to allow replacing empty strings
        # [(ldap.MOD_REPLACE, k, v) for (k,v) in attributes.items()]
        modification_attributes = ldap.modlist.modifyModlist(current_, attributes)

        self.ldap.modify_attributes(dn, modification_attributes)

    def group_modify(self, cn, attributes):
        """Change one or more attributes for a given group.

        @type cn: string representing the common name for the group
        @type attributes:  dictionary with the attribute names and their new values

        @raise: NoSuchGroupError
        """
        dn = "cn=%s,%s" % (cn, self.configuration.group_dn_base)
        current = self.group_filter_search(CnFilter(cn))
        if current is None:
            logging.error("group_modify did not find group with cn = %s (dn = %s)", cn, dn)
            raise NoSuchGroupError(cn)
        logging.debug("group_modify current attribute values = %s - new attribute values = %s",
            current[0], attributes)
        self.__modify(current[0], dn, attributes)

    def user_modify(self, cn, attributes):
        """Change one or more attributes for a given user.

        @type cn: string representing the common name for the user
        @type attributes: dictionary with the attribute names and their new values

        @raise: NoSuchUserError
        """
        dn = "cn=%s,%s" % (cn, self.configuration.user_dn_base)
        current = self.user_filter_search(CnFilter(cn))
        if current is None:
            logging.error("user_modify did not find user with cn = %s (dn = %s)", cn, dn)
            raise NoSuchUserError(cn)
        logging.debug("user_modify current attribute values = %s - new attribute values = %s",
            current[0], attributes)
        self.__modify(current[0], dn, attributes)

    def project_modify(self, cn, attributes):
        """Change one or more attributes for a given project.

        @type cn: string representing the common name for the user
        @type attributes: dictionary with the attribute names and their new values

        @raise: NoSuchProjectError
        """
        dn = "cn=%s,%s" % (cn, self.configuration.project_dn_base)
        current = self.project_filter_search(CnFilter(cn))
        if current is None:
            logging.error("project_modify did not find project with cn = %s (dn = %s)", cn, dn)
            raise NoSuchProjectError(cn)
        logging.debug("project_modify current attribute values = %s - new attribute values = %s",
            current[0], attributes)
        self.__modify(current[0], dn, attributes)

    def user_add(self, cn, attributes):
        """Add the values for the given attributes.

        @type cn: string representing the common name for the user. Together with the subtree, this forms the dn.
        @type attributes: dictionary with attributes for which a value should be added
        """
        dn = "cn=%s,%s" % (cn, self.configuration.user_dn_base)
        self.ldap.add(dn, attributes.items())

    def group_add(self, cn, attributes):
        """Add the values for the given attributes.

        @type cn: string representing the common name for the group. Together with the subtree, this forms the dn.
        @type attributes: dictionary with attributes for which a value should be added
        """
        dn = "cn=%s,%s" % (cn, self.configuration.group_dn_base)
        self.ldap.add(dn, attributes.items())

    def project_add(self, cn, attributes):
        """Add the values for the given attributes.

        @type cn: string representing the common name for the project. Together with the subtree, this forms the dn.
        @type attributes: dictionary with attributes for which a value should be added
        """
        dn = "cn=%s,%s" % (cn, self.configuration.project_dn_base)
        self.ldap.add(dn, attributes.items())


    @TryOrFail(3, (ldap.LDAPError,), 10)
    def get_schema(self, ldap_obj_class_name_or_oid, reload=False, do_reload=False):  #pylint: disable=redefined-builtin
        """Get attributes as provided by schema

        - we only do this once when it is requested
        - we cache the result as this should not change in a single run
        - unless the reload flag is set :-D

        @type ldap_obj_class_name_or_oid: LDAP class name or OID to get the schema from
                                         (passed to ldap.schema.subentry.SubSchema)
        @type reload: deprecated argument, do not use anymore, use do_reload
        @type do_reload: boolean indicating if the schema should be returned form the cache or reloaded from the LDAP
                      server.

        @returns: dictionary containing details about the schema
                  there is an entry for each attribute with the following keys
                  - ['oid'] gives the corresponding oid for the attribute
                  - ['single'] gives True for a single-value attribute, False otherwise

        @raise: LDAPError when the schema cannot be fetched for the given object class
        """
        if reload:
            logging.warning('usage of reload is deprecated, use do_reload instead')
            do_reload = reload

        if self.ldap is None:
            self.bind()

        if not do_reload and ldap_obj_class_name_or_oid in self.schema:
            return self.schema[ldap_obj_class_name_or_oid]

        self.schema[ldap_obj_class_name_or_oid] = {}

        try:
            # returns ('cn=Subschema', <ldap.schema.subentry.SubSchema instance at 0x1986878>)
            schematype, schema = ldap.schema.subentry.urlfetch(self.ldap.ldap_url.unparse())
        except ldap.LDAPError:
            logging.exception("Failed to fetch schema")
            raise

        attributes = {}

        if schematype == 'cn=Subschema':
            try:
                # this returns a list of dicts
                for x in schema.attribute_types([ldap_obj_class_name_or_oid]):
                    attributes.update(x)
            except Exception:
                logging.exception(
                        "Failed to retrieve attributes from schematype %s and ldap_obj_class_name_or_oid %s",
                        schematype, ldap_obj_class_name_or_oid)
                raise
        else:
            logging.error('Unknown returned schematype %s', schematype)

        if len(attributes) == 0:
            logging.error("No attributes from schematype %s and ldap_obj_class_name_or_oid %s",
                           schematype, ldap_obj_class_name_or_oid)
            return None

        for attr in attributes.values():
            oid = attr.oid
            single = attr.single_value == 1
            name = attr.names[0]
            if len(attr.names) > 1:
                # what with multiple names?
                logging.error("Multiple names associated with attr, only using first one. From %s: oid %s names %s",
                               ldap_obj_class_name_or_oid, oid, attr.names)

            self.schema[ldap_obj_class_name_or_oid][name] = {}
            self.schema[ldap_obj_class_name_or_oid][name]['single'] = single
            self.schema[ldap_obj_class_name_or_oid][name]['oid'] = oid

        return self.schema[ldap_obj_class_name_or_oid]


class LdapEntity(object):
    """Base class for all things LDAP that work on a higher level."""

    def __init__(self, object_classes=None):
        """Initialisation.

        Note that the LdapQuery singleton should have been instantiated elsewhere.
        """
        if not object_classes:
            object_classes = []
        self.ldap_query = LdapQuery(None)
        self.ldap_info = None

        self.object_classes = object_classes  # LDAP object class name for which the schema will be checked

    def get_ldap_info(self):
        return None

    def modify_ldap(self, attributes):
        """Actually make modifications in the LDAP.

        @type attributes: dictionary with the required LDAP values

        Should be iplemented by deriving classes.
        """
        pass

    def __getattr__(self, name):
        """Getter for the LdapUser fields. Only accessed for fields that are in
        the ldap_info dictionary or in the schema for the given object classes,
        since these are not set in the instance itself. Otherwise, we never end up here.

        @returns: the value corresponding to the 'name' attribute in LDAP
        """

        try:
            new_ldap_info = object.__getattribute__(self, 'ldap_info')
            if new_ldap_info is None:
                new_ldap_info = self.get_ldap_info()
                object.__setattr__(self, 'ldap_info', new_ldap_info)
        except AttributeError:
            logging.exception("Tried to access an unknown attribute %s", name)
            raise

        if new_ldap_info and name in new_ldap_info:
            return new_ldap_info[name]
        else:
            object_classes = object.__getattribute__(self, 'object_classes')
            join = lambda it: (y for x in it for y in x)
            attributes = list(join([self.ldap_query.get_schema(o).keys() for o in object_classes]))
            if name in attributes:
                return None

            return object.__getattribute__(self, name)

    def __setattr__(self, name, value):
        """Setter for the LdapUser fields. Makes the change persistent in the LDAP database.

        @type name: name of the field and the corresponding attribute in the LDAP database for an entry in the ou=people
                    subtree
        @type value: the value to store. This will be turned into a list on the fly for non-multivalued LDAP attributes

        @raise: LDAPError if the change cannot be made persistent. In that case, the instance field will not be changed
                either.
        """
        try:
            ldap_info = object.__getattribute__(self, 'ldap_info')
            object_classes = object.__getattribute__(self, 'object_classes')
            join = lambda it: (y for x in it for y in x)
            attributes = list(join([self.ldap_query.get_schema(o).keys() for o in object_classes]))
            if ldap_info and name in attributes:
                ldap_value = value
                if not isinstance(value, list):
                    ldap_value = [value]
                try:
                    self.modify_ldap({name: ldap_value})
                    self.ldap_info[name] = value
                except ldap.LDAPError:
                    logging.error("Could not save the new value %s for %s with cn=%s to the LDAP",
                                   value, name, self.vsc_user_id)
                    pass
            else:
                object.__setattr__(self, name, value)
        except AttributeError:
            # in this case, insufficient initialisation, and we simply set the
            # values directly
            object.__setattr__(self, name, value)
