#!/usr/bin/env python
##
#
# copyright 2012 andy georges
#
# this file is part of vsc-tools,
# originally created by the hpc team of the university of ghent (http://ugent.be/hpc).
#
#
# http://github.com/hpcugent/vsc-tools
#
# vsc-tools is free software: you can redistribute it and/or modify
# it under the terms of the gnu general public license as published by
# the free software foundation v2.
#
# vsc-tools is distributed in the hope that it will be useful,
# but without any warranty; without even the implied warranty of
# merchantability or fitness for a particular purpose. see the
# gnu general public license for more details.
#
# you should have received a copy of the gnu general public license
# along with vsc-tools. if not, see <http://www.gnu.org/licenses/>.
##
"""Timestamp tools for this LDAP library."""

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

    elif isinstance(timestamp, str):
        tmp = datetime.datetime.strptime(timestamp, LDAP_DATETIME_TIMEFORMAT)
        return (tmp.replace(tzinfo=utc).astimezone(Local), timestamp)


def read_timestamp(filename):
    """Read the stored timestamp value from a pickled file.

    @returns: string representing a timestamp in the proper LDAP time format

    """
    cache = FileCache(filename)
    (_, timestamp) = cache.load(0)

    if not timestamp is None and timestamp.tzinfo is None:
        # add local timezoneinfo
        timestamp = timestamp.replace(tzinfo=Local)

    return timestamp


def write_timestamp(filename, timestamp):
    """Write the given timestamp to a pickled file.

    @type timestamp: datetime.datetime timestamp
    """

    if timestamp.tzinfo is None:
        # add local timezoneinfo
        timestamp = timestamp.replace(tzinfo=Local)

    cache = FileCache(filename)
    cache.update(0, timestamp, 0)
    cache.close()
