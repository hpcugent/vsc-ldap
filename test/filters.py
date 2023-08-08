# -*- coding: utf-8 -*-
#
# Copyright 2009-2023 Ghent University
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
Unit tests for the vsc.ldap.filters.


@author: Andy Georges (Ghent University)
"""

import copy
import random
import string
from vsc.install.testing import TestCase

from vsc.ldap.filters import LdapFilter


class SingleChoiceGenerator(object):
    """Provides a list of exhausting choices, reducing the choices until in each iteration."""
    def __init__(self, values):
        self.values = values

    def next(self):
        if not self.values:
            return None

        v = random.choice(self.values)
        self.values.remove(v)
        return v


class LdapFilterGenerator(object):
    """Generates random LdapFilter instances"""

    def __init__(self):

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


    def next(self):

        ldap_filter = None
        attributes = copy.deepcopy(self.attributes)
        attribute_choice = SingleChoiceGenerator(attributes)

        size = random.randint(1, random.randint(1, len(self.attributes)))
        for d in range(0, size):

            op = random.choice(self.operators)
            at = attribute_choice.next()

            new = LdapFilter("%s=%s" % (at, ''.join([random.choice(string.printable) for x in range(16)])))

            if not ldap_filter:
                ldap_filter = LdapFilter(new)
            else:
                if op == LdapFilter.negate:
                    ldap_filter = op(ldap_filter)
                else:
                    if random.choice([True, False]):
                        ldap_filter = op(new, ldap_filter)
                    else:
                        ldap_filter = op(ldap_filter, new)

        return ldap_filter

LFG = LdapFilterGenerator()

class TestLdapFilter(TestCase):

    def test_and(self):
        """Test the and operator for combining two filters."""
        left = LFG.next()
        right = LFG.next()
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

    def test_or(self):
        """Test the or operator for combining two filters."""
        left = LFG.next()
        right = LFG.next()
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

    def test_negate(self):
        """Test the negation operator of a filter."""
        left = LFG.next()
        negation = left.negate()

        negation_string = "%s" % (negation)

        self.assertTrue(negation_string[0] == '(')
        self.assertTrue(negation_string[1] == '!')
        self.assertTrue(negation_string[-1] == ')')

    def test_from_list_and(self):
        """Test the formation of a filters from a given list of filters using the and operator."""
        fs = [LFG.next() for x in range(random.randint(2,30))]

        combination = LdapFilter.from_list(lambda x, y: x & y, fs)
        combination_string = "%s" % (combination)

        self.assertTrue(len(combination_string) <= 3 + sum(map(lambda f: len("%s" % (f)), fs)))

        self.assertTrue(combination_string[0] == '(')
        self.assertTrue(combination_string[1] == '&')
        self.assertTrue(combination_string[-1] == ')')
