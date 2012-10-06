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
This module contains classes that allow constructing filter for an LDAP search in
a straightforward and intuitive manner.

Examples:

from vsc.ldap.filter import LdapFilter

>>> f = LdapFilter("x=4")
>>> g = LdapFilter("y=5")
>>> h = LdapFilter("z=3")

>>> print "f = %s" % f
f = (x=4)
>>> print "g = %s" % g
g = (y=5)
>>> print "h = %s" % h
h = (z=3)

>>> print "f & g -> %s" % (f & g)
f & g -> (& (x=4) (y=5))
>>> print "f -> %s" % f
f -> (x=4)
>>> print "g -> %s" % g
g -> (y=5)

>>> print "(f & g) | h -> %s" % ((f & g) | h)
(f & g) | h -> (| (& (x=4) (y=5)) (z=3))
>>> print "f & g | h -> %s" % (f & g | h)
f & g | h -> (| (& (x=4) (y=5)) (z=3))
>>> print "f & (g | h) -> %s" % (f & (g | h))
f & (g | h) -> (& (x=4) (| (y=5) (z=3)))

>>> print "f & g & h -> %s" % (f & g & h)
f & g & h -> (& (x=4) (y=5) (z=3))
>>> print "f & g & h | f -> %s" % (f & g & h | f)
f & g & h | f -> (| (& (x=4) (y=5) (z=3)) (x=4))
>>> print "! f -> %s" % (f.negate())
! f -> (! (x=4) )

>>> print "fold & [f,g,h] -> %s" % LdapFilter.from_list(lambda x, y: x & y, [f, g, h])
fold & [f,g,h] -> (& (x=4) (y=5) (z=3))
>>> print "fold | [f,g,h] -> %s" % LdapFilter.from_list(lambda x, y: x | y, [f, g, h])
fold | [f,g,h] -> (| (x=4) (y=5) (z=3))
>>> print "fold & [f,g,h, g=1] -> %s" % LdapFilter.from_list(lambda x, y: x & y, [f, g, h, "g=1"])
fold & [f,g,h, g=1] -> (& (x=4) (y=5) (z=3) (g=1))
"""
import copy

from vsc.ldap.ldap_utils import convertTimestamp


class LdapFilterError(Exception):
    pass


class LdapFilter(object):
    """Representing an LDAP filter with operators between the filter values.

    This is implemented as a tree, where the nodes are the operations, e.g.,
    and, or, ... and the leaves are the values to finally concatenate to
    a single filter when printing out the tree.

    If you have multiple key value pairs that would wish to concatenate using a single
    operator, for example to take the AND of them, the static from_list method will do
    just that.

    Note that for usage in a search, the resulting filter should be transformed into a
    string, if the tools are not doing that automagically :)

    Note that all operations are left associative.
    """
    def __init__(self, value):
        """Initialises the filter with a single value to filter on."""
        self.root = value
        self.left = None
        self.right = None

    @staticmethod
    def from_list(operator, ls):
        """Turns the given list into a filter using the given operator as the combinator.

        @returns: LdapFilter instance representing the filter.
        """
        if ls and len(ls) > 0:
            if not isinstance(ls[0], LdapFilter):
                initialiser = LdapFilter(ls[0])
            else:
                initialiser = ls[0]
            return reduce(lambda x, y: operator(x, y), ls[1:], initialiser)
        else:
            raise LdapFilterError()

    def __and__(self, value):
        """Return a new filter that is the logical and operator of this filter and the provided value.

        It merges the currect filter with the value. The currect filter becomes the
        left subtree of the new filter, the value becomes the right subtree.

        @type value: This can be a string or an LdapFilter instance. In the former case,
                     first a new LdapFilter instance is made, such that all leaves are
                     actually LdapFilter instances.
        @returns: the new filter instance
        """
        if not isinstance(value, LdapFilter):
            value = LdapFilter(value)
        elif self == value:
            value = copy.deepcopy(self)

        return self._combine("&", value)

    def __or__(self, value):
        """Return a new filter that is the logical or operator of this filter and the provided value.

        It merges the currect filter with the value. The currect filter becomes the
        left subtree of the new filter, the value becomes the right subtree.

        @type value: This can be a string or an LdapFilter instance. In the former case,
                     first a new LdapFilter instance is made, such that all leaves are
                     actually LdapFilter instances.
        @returns: the new filter instance
        """
        if not isinstance(value, LdapFilter):
            value = LdapFilter(value)
        elif self == value:
            value = copy.deepcopy(self)

        return self._combine("|", value)

    def negate(self):
        """Return a new filter that represents the negation of the current filter.

        @returns: the new filter instance
        """
        return self._combine("!", None)

    def __str__(self):
        """Converts the LdapFilter instance to a string."""
        return self._to_string()

    def _to_string(self, previous_operator=None):
        """Pretty prints the filter, such that it can be used in the calls to the LDAP library."""

        if self.left is None:
            # single value, self.root should be a string not representing an operator
            return "(%s)" % (self.root)

        left_string = self.left._to_string(self.root)
        if not self.right is None:
            right_string = self.right._to_string(self.root)
        else:
            right_string = ""

        if self.root == previous_operator:
            return "%s %s" % (left_string, right_string)
        else:
            return "(%s %s %s)" % (self.root, left_string, right_string)

    def _combine(self, operator, value=None):
        """Updates the tree with a new root, i.e., the given operator and
        the value.

        Thew original tree becomes the left child tree, the value the right.

        @type value: Either an LdapFilter instance or None (default)

        @returns: the updated instance.
        """

        new = copy.deepcopy(self)
        old = copy.copy(new)
        new.root = operator
        new.left = old
        new.right = value

        return new


class TimestampFilter(LdapFilter):
    """Represents a filter that aims to find entries that are compared to a given timestamp."""
    def __init__(self, value, timestamp, comparator):
        """Initialise the filter.

        @type value: string representing a filter
        @type timestamp: string or datetime instance representing a timestamp. This value
                         will be converted to a format LDAP groks.
        @type comparator: string representing a comparison operation, e.g., <=, >=
        """
        super(TimestampFilter, self).__init__(value)
        self.timestamp = convertTimestamp(timestamp)[1]
        if comparator != '>=' and comparator != '<=':
            raise LdapFilterError()
        self.comparator = comparator

    def __str__(self):
        """Converts the filter to an LDAP understood string."""
        return "(& (modifyTimestamp%s%s) %s)" % (self.comparator,
                                                 self.timestamp,
                                                 super(TimestampFilter, self).__str__())


class NewerThanFilter(TimestampFilter):
    """Represents a filter that aims to find entries that are newer than the given timestamp."""
    def __init__(self, value, timestamp):
        """Initialise the filter.

        @type value: string representing a filter
        @type timestamp: string or datetime instance representing a timestamp. This value
                         will be converted to a format LDAP groks.
        """
        super(NewerThanFilter, self).__init__(value, timestamp, '>=')


class OlderThanFilter(TimestampFilter):
    """Represents a filter that aims to find entries that are older than the given timestamp."""
    def __init__(self, value, timestamp):
        """Initialise the filter.

        @type value: string representing a filter
        @type timestamp: string or datetime instance representing a timestamp. This value
                         will be converted to a format LDAP groks.
        """
        super(OlderThanFilter, self).__init__(value, timestamp, '<=')
