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
"""Convenience classes for using the VSC LDAP.
"""
import ldap
import ldap.modlist
import re

import vsc.fancylogger as fancylogger

from vsc.dateandtime import Local
from vsc.ldap.ldap_utils import LdapConnection, LdapConfiguration
from vsc.ldap.filter import LdapFilter
from vsc.ldap import NoSuchUserError, NoSuchGroupError, NoSuchProjectError
from vsc.utils.patterns import Singleton

log = fancylogger.getLogger(name='vsc.ldap.utils')


class SchemaConfiguration(LdapConfiguration):
    """Represents an LDAP configuration with some extra schema-related information."""

    def __init__(self):
        super(SchemaConfiguration, self).__init__()

        self.user_dn_base = None
        self.group_dn_base = None
        self.project_dn_base = None

        self.user_multi_value_attributes = None
        self.group_multi_value_attributes = None
        self.project_multi_value_attributes = None


class LdapQuery:
    """Singleton class to interact with the LDAP server.

    This level is LDAP-schema aware. It knows about the dn for people, groups, VOs and projects.

    Allows searching for
        - users
        - groups
        - VOs (these are a VSC-specific thingie, in LDAP they're simply groups)
    """
    __metaclass__ = Singleton

    def __init__(self, configuration):
        """
        Initalisation.

        @type configuration: a SchemaConfiguration instance.

        If you initialise using None as the configuration, this will not fail
        if the singleton has already been created.
        """
        self.logger = fancylogger.getLogger(name=self.__class__.__name__)
        self.configuration = configuration
        self.ldap = LdapConnection(configuration)

        self.ldap.connect()
        self.ldap.bind()

    def group_filter_search(self, filter, attributes=None):
        """Perform an LDAP lookup in the group tree, based on the given filter.

        @type filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all retrieved attributes.

        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if not self.ldap:
            self.logger.error("LDAP search request (group_filter_search) failed: ldap not initialised")
            raise ldap.OTHER()

        if isinstance(filter, LdapFilter):
            filter = str(filter)

        # for groups, we use the following base
        self.logger.info("group_filter_search: filter = %s, requested attributes = %s" % (filter, attributes))
        base = self.configuration.group_dn_base
        entries = self.ldap.search(filter, base, attributes)
        results = [self.__delist_ldap_return_value(e, self.configuration.group_multi_value_attributes, attributes)
                   for e in entries]
        self.logger.debug("group_filter_search finds %d results" % (len(results)))
        return results

    def group_search(self, cn, member_uid, attributes=None):
        """Perform an LDAP lookup in the group tree, looking for the entry with given cn and memberUid.

        @type cn: string representing the desired common name in the LDAP database
        @type member_uid: string representing the member's user id in the LDAP database?
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all the retrieved attributes

        @returns: the matching LDAP entry as a dictionary, limited to the requested attributes.
        """
        self.logger.info("group_search: cn = %s, member_uid = %s, requested attributes = %s"
                         % (cn, member_uid, attributes))
        result = self.group_filter_search("(&(cn=%s) (memberUid=%s))" % (cn, member_uid), attributes)
        self.logger.debug("group_search for %s, %s yields %s" % (cn, member_uid, result))
        if not result is None and len(result) > 0:
            return result[0]
        else:
            self.logger.debug("group_search returning None")
            return None

    def vo_filter_search(self, filter, attributes=None):
        """Perform an LDAP lookup for VOs, based on the given filter.

        @type filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all the retrieved attributes.
        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if isinstance(filter, LdapFilter):
            filter = str(filter)

        self.logger.info("vo_filter_search: filter = %s, requested attributes = %s" % (filter, attributes))
        if attributes and not 'cn' in attributes:
            attributes.append('cn')
        results = self.group_filter_search(filter, attributes)
        if not results is None:
            vo_name_regex = re.compile(r"^(a|b|g|l|v)vo\d{5}$")
            results = [r for r in results if len(r) > 0 and vo_name_regex.search(r['cn'])]
            self.logger.debug("vo_filter_search retains %d results after applying VO filter" % (len(results)))
            return results
        else:
            self.logger.debug("vo_filter_search returning None")
            return []

    def no_vo_filter_search(self, filter, attributes=None):
        """Perform an LDAP lookup for non-VO groups, based on the given filter.

        @type filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all the retrieved attributes.
        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if isinstance(filter, LdapFilter):
            filter = str(filter)

        self.logger.info("no_vo_filter_search: filter = %s, requested attributes = %s" % (filter, attributes))
        if attributes and not 'cn' in attributes:
            attributes.append('cn')
        results = self.group_filter_search(filter, attributes)
        if not results is None:
            vo_name_regex = re.compile(r"^(a|b|g|l|v)vo\d{5}$")
            results = [r for r in results if not vo_name_regex.search(r['cn'])]
            self.logger.debug("no_vo_filter_search retains %d results after applying VO filter" % (len(results)))
            return results
        else:
            self.logger.debug("no_vo_filter_search returning None")
            return []

    def vo_search(self, cn, member_uid, attributes=None):
        """Perform an LDAP lookup in the group tree, looking for the VO with given cn and memberUid.

        @type cn: string representing the desired common name in the LDAP database
        @type member_uid: string representing the member's user id in the LDAP database?
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all the retrieved attributes
        @returns: the matching LDAP entry as a dictionary, limited to the requested attributes.
        """
        result = self.vo_filter_search("(&(cn=%s) (memberUid=%s))" % (cn, member_uid), attributes)
        self.logger.debug("vo_search for %s, %s yields %s" % (cn, member_uid, result))
        if not result is None and len(result) > 0:
            return result[0]
        else:
            self.logger.debug("vo_search returning None")
            return None

    def no_vo_search(self, cn, member_uid, attributes=None):
        """Perform an LDAP lookup in the group tree, looking for the non-VO entry with given cn and memberUid.

        @type cn: string representing the desired common name in the LDAP database
        @type member_uid: string representing the member's user id in the LDAP database?
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all the retrieved attributes

        @returns: the matching LDAP entry as a dictionary, limited to the requested attributes.
        """
        result = self.no_vo_filter_search("(&(cn=%s) (memberUid=%s))" % (cn, member_uid), attributes)
        self.logger.debug("no_vo_search for %s, %s yields %s" % (cn, member_uid, result))
        if not result is None and len(result) > 0:
            return result[0]
        else:
            self.logger.debug("no_vo_search returning None")
            return None

    def project_filter_search(self, filter, attributes=None):
        """Perform an LDAP lookup in the projects tree, based on the given filter.

        @type filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all retrieved attributes

        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if not self.ldap:
            self.logger.error("LDAP search request (user_filter_search) failed: ldap not initialised")
            raise ldap.OTHER()

        if isinstance(filter, LdapFilter):
            filter = str(filter)

        self.logger.info("project_filter_search: filter = %s, requested attributes = %s" % (filter, attributes))
        base = self.configuration.project_dn_base
        entries = self.ldap.search(filter, base, attributes)
        results = [self.__delist_ldap_return_value(e, self.configuration.project_multi_value_attributes, attributes)
                   for e in entries]
        self.logger.debug("project_filter_search finds %d results" % (len(results)))
        return results

    def user_filter_search(self, filter, attributes=None):
        """Perform an LDAP lookup in the user tree, based on the given filter.

        @type filter: string describing an LDAP filter or LdapFilter instance
        @type attributes: list of strings describing LDAP attributes. If this is
                          None (default), we return all retrieved attributes

        @returns: list of matching LDAP entries as dictionaries, limited to the requested attributes.

        @raise ldap.OTHER if the LDAP connection was not properly instantiated
        """
        if not self.ldap:
            self.logger.error("LDAP search request (user_filter_search) failed: ldap not initialised")
            raise ldap.OTHER()

        if isinstance(filter, LdapFilter):
            filter = str(filter)

        # For users, we use the following base:
        self.logger.info("group_filter_search: filter = %s, requested attributes = %s" % (filter, attributes))
        base = self.configuration.user_dn_base
        entries = self.ldap.search(filter, base, attributes)
        results = [self.__delist_ldap_return_value(e, self.configuration.user_multi_value_attributes, attributes)
                   for e in entries]
        self.logger.debug("user_filter_search finds %d results" % (len(results)))
        return results

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
        result = self.user_filter_search("(&(instituteLogin=%s) (institute=%s))" % (user_id, institute), attributes)
        self.logger.debug("user_search for %s, %s yields %s" % (user_id, institute, result))
        if not result is None and len(result) > 0:
            return result[0]
        else:
            self.logger.debug("user_search returning None")
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
        kvs = [(k, v[0]) for (k, v) in entry.iteritems()
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
        # [(ldap.MOD_REPLACE, k, v) for (k,v) in attributes.iteritems()]
        modification_attributes = ldap.modlist.modifyModlist(current_, attributes)

        self.ldap.modify_attributes(dn, modification_attributes)

    def group_modify(self, cn, attributes):
        """Change one or more attributes for a given group.

        @type cn: string representing the common name for the group
        @type attributes:  dictionary with the attribute names and their new values

        @raise: NoSuchGroupError
        """
        dn = "cn=%s,%s" % (cn, self.configuration.group_dn_base)
        current = self.group_filter_search("(cn=%s)" % (cn))
        if current is None:
            self.logger.error("group_modify did not find group with cn = %s (dn = %s)" % (cn, dn))
            raise NoSuchGroupError(cn)
        self.logger.debug("group_modify current attribute values = %s - new attribute values = %s"
                          % (current[0], attributes))
        self.__modify(current[0], dn, attributes)

    def user_modify(self, cn, attributes):
        """Change one or more attributes for a given user.

        @type cn: string representing the common name for the user
        @type attributes: dictionary with the attribute names and their new values

        @raise: NoSuchUserError
        """
        dn = "cn=%s,%s" % (cn, self.configuration.user_dn_base)
        current = self.user_filter_search("(cn=%s)" % (cn))
        if current is None:
            self.logger.error("user_modify did not find user with cn = %s (dn = %s)" % (cn, dn))
            raise NoSuchUserError(cn)
        self.logger.debug("user_modify current attribute values = %s - new attribute values = %s"
                          % (current[0], attributes))
        self.__modify(current[0], dn, attributes)

    def project_modify(self, cn, attributes):
        """Change one or more attributes for a given project.

        @type cn: string representing the common name for the user
        @type attributes: dictionary with the attribute names and their new values

        @raise: NoSuchProjectError
        """
        dn = "cn=%s,%s" % (cn, self.configuration.project_dn_base)
        current = self.project_filter_search("(cn=%s)" % (cn))
        if current is None:
            self.logger.error("project_modify did not find project with cn = %s (dn = %s)" % (cn, dn))
            raise NoSuchProjectError(cn)
        self.logger.debug("project_modify current attribute values = %s - new attribute values = %s"
                          % (current[0], attributes))
        self.__modify(current[0], dn, attributes)

    def user_add(self, cn, attributes):
        """Add the values for the given attributes.

        @type cn: string representing the common name for the user. Together with the subtree, this forms the dn.
        @type attributes: dictionary with attributes for which a value should be added
        """
        dn = "cn=%s,%s" % (cn, self.configuration.user_dn_base)
        self.ldap.add(dn, attributes.items())

    def vo_add(self, cn, attributes):
        """Add the values for the given attributes.

        @type cn: string representing the common name for the VO. Together with the subtree, this forms the dn.
        @type attributes: dictionary with attributes for which a value should be added
        """
        self.group_add(cn, attributes)

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

    def get_schema(self, ldap_obj_class_name_or_oid):
        """Get attributes as provided by schema
        @type ldap_obj_class_name_or_oid: LDAP class name or OID to get the schema from
                                         (passed to ldap.schema.subentry.SubSchema)

        @raise:
        """
        if self.ldap is None:
            self.bind()

        try:
            # returns ('cn=Subschema', <ldap.schema.subentry.SubSchema instance at 0x1986878>)
            schematype, schema = ldap.schema.subentry.urlfetch(self.ldapurl.unparse())
        except Exception, _:
            self.log.exception("Failed to fetch schema from url")
            raise

        attributes = {}
        if schematype == 'cn=Subschema':
            try:
                # this returns a list of dicts
                for x in schema.attribute_types([ldap_obj_class_name_or_oid]):
                    attributes.update(x)
            except:
                self.log.exception("Failed to retrieve attributes from schematype %s and ldap_obj_class_name_or_oid %s"
                                   % (schematype, ldap_obj_class_name_or_oid))
                raise
        else:
            self.log.error('Unknown returned schematype %s' % schematype)

        if len(attributes) == 0:
            self.log.error("No attributes from schematype %s and ldap_obj_class_name_or_oid %s"
                           % (schematype, ldap_obj_class_name_or_oid))
            return

        for attr in attributes.values():
            oid = attr.oid
            single = attr.single_value == 1
            if len(attr.names) > 1:
                # what with multiple names?
                self.log.error("Multiple names associated with attr, only using first one. From %s: oid %s names %s"
                               % (ldap_obj_class_name_or_oid, oid, attr.names))
            name = attr.names[0]

            if single:
                self.attr[name] = None
            else:
                self.attr[name] = []

            self.attr2oid[name] = oid


class LdapEntity(object):
    """Base class for all things LDAP that work on a higher level."""

    def __init__(self):
        """Initialisation.

        Note that the LdapQuery singleton should have been instantiated elsewhere.
        """
        self.ldap_query = LdapQuery(None)
        self.ldap_info = None
        self.logger = fancylogger.getLogger(self.__class__.__name__)

    def get_ldap_info(self):
        pass

    def modify_ldap(self, attributes):
        """Actually make modifications in the LDAP.

        @type attributes: dictionary with the required LDAP values

        Should be iplemented by deriving classes.
        """
        pass

    def __getattr__(self, name):
        """Getter for the LdapUser fields. Only accessed for fields that are in
        the ldap_info dictionary, since these are not set in the instance
        itseld. Otherwise, we never end up here.

        @returns: the value corresponding to the 'name' atrribute in LDAP
        """

        try:
            new_ldap_info = object.__getattribute__(self, 'ldap_info')
            if new_ldap_info is None:
                new_ldap_info = self.get_ldap_info()
                object.__setattr__(self, 'ldap_info', new_ldap_info)
        except AttributeError, _:
            raise

        if new_ldap_info and name in new_ldap_info:
            return new_ldap_info[name]
        else:
            object.__getattribute__(self, name)

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
            if ldap_info and name in ldap_info:
                ldap_value = value
                if type(value) != list:
                    ldap_value = [value]
                try:
                    self.modify_ldap({name: ldap_value})
                    self.ldap_info[name] = value
                except ldap.LDAPError, _:
                    self.logger.error("Could not save the new value %s for %s with cn=%s to the HPC LDAP"
                                      % (value, name, self.vsc_user_id))
                    pass
            else:
                object.__setattr__(self, name, value)
        except AttributeError, _:
            # in this case, insufficient initialisation, and we simply set the
            # values directly
            object.__setattr__(self, name, value)


def read_timestamp(timestamp_pickle):
    """Read the stored timestamp value from a pickled file.

    @returns: string representing a timestamp in the proper LDAP time format

    """
    timestamp = timestamp_pickle.read()

    if not timestamp is None and timestamp.tzinfo is None:
        # add local timezoneinfo
        timestamp = timestamp.replace(tzinfo=Local)

    return timestamp


def write_timestamp(timestamp_pickle, timestamp):
    """Write the given timestamp to a pickled file.

    @type timestamp: datetime.datetime timestamp
    """

    if timestamp.tzinfo is None:
        # add local timezoneinfo
        timestamp = timestamp.replace(tzinfo=Local)

    timestamp_pickle.write(timestamp)


if __name__ == '__main__':
    pass
