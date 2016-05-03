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
Setup for the vsc ldap utilities

@author: Andy Georges
@author: Stijn De Weirdt
@author: Wouter Depypere
@author: Kenneth Hoste
"""

import vsc.install.shared_setup as shared_setup
from vsc.install.shared_setup import ag, kh, sdw, wdp, jt

PACKAGE = {
    'install_requires': [
        'vsc-base >= 2.4.16',
        'vsc-utils>= 1.8.2',
        'python-ldap'
    ],
    'version': '1.4.0',
    'author': [ag, kh, sdw, wdp, jt],
    'maintainer': [ag],
    'dependency_links': [
        "git+https://github.com/hpcugent/vsc-utils.git#egg=vsc-utils-1.8.2",
    ],

}

if __name__ == '__main__':
    shared_setup.action_target(PACKAGE)
