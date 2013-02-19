#!/usr/bin/env python
# -*- coding: latin-1 -*-
##
# Copyright 2009-2012 Ghent University
#
# This file is part of vsc-ldap
# originally created by the HPC team of Ghent University (http://ugent.be/hpc/en),
# with support of Ghent University (http://ugent.be/hpc),
# the Flemish Supercomputer Centre (VSC) (https://vscentrum.be/nl/en),
# the Hercules foundation (http://www.herculesstichting.be/in_English)
# and the Department of Economy, Science and Innovation (EWI) (http://www.ewi-vlaanderen.be/en).
#
# http://github.com/hpcugent/vsc-ldap
#
# vsc-ldap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation v2.
#
# vsc-ldap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with vsc-ldap. If not, see <http://www.gnu.org/licenses/>.
##
"""
Unit tests for the vsc.ldap.filters.


@author: Andy Georges (Ghent University)
"""

import copy
from operator import __and__
import random

# support for paycheck in Python 2.4
try:
    import functools
except ImportError, _:
    import functools_backport_24 as functools


import paycheck.generator
from paycheck import with_checker
from paycheck.generator import BooleanGenerator, ChoiceGenerator, IntGenerator, PayCheckGenerator, StringGenerator
from unittest import TestCase, TestLoader, main

from vsc.ldap.filters import LdapFilter


class LdapAttributeStringGenerator(StringGenerator):
    """Generate random string for use in LDAP filters.

    Size should be limited!
    """
    def __init__(self, max_length):
        """Initialise."""
        super(LdapAttributeStringGenerator, self).__init__()
        self.max_length = max_length

    def __next__(self):
        """Get the next random string."""
        length = random.randint(0, self.max_length)
        return ''.join([chr(random.randint(ord('a'), ord('z'))) for x in xrange(length)])


class SingleChoiceGenerator(PayCheckGenerator):
    """Provides a list of exhausting choices, reducing the choices until in each iteration."""
    def __init__(self, values):
        self.values = values

    def next(self):
        if not self.values:
            return None

        v = random.choice(self.values)
        self.values.remove(v)
        return v


class LdapFilterGenerator(PayCheckGenerator):
    """Generates random LdapFilter instances"""

    def __init__(self):
        #super(LdapFilterGenerator, self).__init__()

        self.attributes = [
            'cn',
            'status',
            'institute',
            'memberUid',
            'moderator',
        ]

        self.operators = (
            LdapFilter.__and__,
            LdapFilter.__or__,
            LdapFilter.negate,
        )

        self.depth = IntGenerator(min=1, max=len(self.attributes))
        self.operator_choice = ChoiceGenerator(self.operators)
        self.value_generator = LdapAttributeStringGenerator(16)
        self.side_generator = BooleanGenerator()

    def next(self):

        ldap_filter = None
        attributes = copy.deepcopy(self.attributes)
        attribute_choice = SingleChoiceGenerator(attributes)

        size = random.randint(1, self.depth.next())

        for d in xrange(0, size):

            op = self.operator_choice.next()
            at = attribute_choice.next()

            new = LdapFilter("%s=%s" % (at, self.value_generator.next()))

            if not ldap_filter:
                ldap_filter = LdapFilter(new)
            else:
                if op == LdapFilter.negate:
                    ldap_filter = op(ldap_filter)
                else:
                    if self.side_generator.next():
                        ldap_filter = op(new, ldap_filter)
                    else:
                        ldap_filter = op(ldap_filter, new)

        return ldap_filter


paycheck.generator.scalar_generators[LdapFilter] = LdapFilterGenerator
paycheck.generator.__all__.append('LdapFilterGenerator')


class TestLdapFilter(TestCase):

    @with_checker(LdapFilter, LdapFilter)
    def test_and(self, left, right):
        """Test the and operator for combining two filters."""
        combination = (left & right)

        left_string = "%s" % (left)
        right_string = "%s" % (right)
        combination_string = "%s" % (combination)

        self.assertTrue(len(combination_string) <= 3 + len(left_string) + len(right_string))
        self.assertTrue(combination_string[0] == '(')
        self.assertTrue(combination_string[1] == '&')
        self.assertTrue(combination_string[-1] == ')')

        if left.root == '&':
            self.assertFalse(combination_string[3] == '&')

    @with_checker(LdapFilter, LdapFilter)
    def test_or(self, left, right):
        """Test the or operator for combining two filters."""
        combination = left | right

        left_string = "%s" % (left)
        right_string = "%s" % (right)
        combination_string = "%s" % (combination)

        self.assertTrue(len(combination_string) <= 3 + len(left_string) + len(right_string))
        self.assertTrue(combination_string[0] == '(')
        self.assertTrue(combination_string[1] == '|')
        self.assertTrue(combination_string[-1] == ')')

        if left.root == '|':
            self.assertFalse(combination_string[3] == '|')

    @with_checker(LdapFilter)
    def test_negate(self, left):
        """Test the negation operator of a filter."""
        negation = left.negate()

        negation_string = "%s" % (negation)

        self.assertTrue(negation_string[0] == '(')
        self.assertTrue(negation_string[1] == '!')
        self.assertTrue(negation_string[-1] == ')')

    @with_checker([LdapFilter])
    def test_from_list_and(self, fs):
        """Test the formation of a filters from a given list of filters using the and operator."""

        if not fs or len(fs) < 2:
            return

        combination = LdapFilter.from_list(lambda x, y: x & y, fs)
        combination_string = "%s" % (combination)

        self.assertTrue(len(combination_string) <= 3 + sum(map(lambda f: len("%s" % (f)), fs)))

        self.assertTrue(combination_string[0] == '(')
        self.assertTrue(combination_string[1] == '&')
        self.assertTrue(combination_string[-1] == ')')


def suite():
    """ return all the tests"""
    return TestLoader().loadTestsFromTestCase(TestLdapFilter)

if __name__ == '__main__':
    main()
