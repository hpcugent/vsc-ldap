# -*- coding: latin-1 -*-
#
# Copyright 2009-2016 Ghent University
#
# This file is part of vsc-ldap,
# originally created by the HPC team of Ghent University (http://ugent.be/hpc/en),
# with support of Ghent University (http://ugent.be/hpc),
# the Flemish Supercomputer Centre (VSC) (https://vscentrum.be/nl/en),
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
"""Timestamp tools for this LDAP library.

@author: Andy Georges
@author: Stijn De Weirdt
"""

import datetime

from vsc.utils.cache import FileCache
from vsc.utils.dateandtime import Local, utc

LDAP_DATETIME_TIMEFORMAT = "%Y%m%d%H%M%SZ"


def convert_timestamp(timestamp=None):
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

    elif isinstance(timestamp, basestring):
        tmp = datetime.datetime.strptime(timestamp, LDAP_DATETIME_TIMEFORMAT)
        return (tmp.replace(tzinfo=utc).astimezone(Local), timestamp)


def read_timestamp(filename):
    """Read the stored timestamp value from a pickled file.

    @returns: string representing a timestamp in the proper LDAP time format

    """
    cache = FileCache(filename)
    (_, timestamp) = cache.load('timestamp')

    return timestamp


def write_timestamp(filename, timestamp):
    """Write the given timestamp to a pickled file.

    @type timestamp: datetime.datetime timestamp
    """

    if isinstance(timestamp, datetime.datetime) and timestamp.tzinfo is None:
        # add local timezoneinfo
        timestamp_ = timestamp.replace(tzinfo=Local)
        (_, timestamp_) = convert_timestamp(timestamp)
    else:
        timestamp_ = timestamp

    cache = FileCache(filename)
    cache.update('timestamp', timestamp_, 0)
    cache.close()
