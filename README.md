# vsc-ldap

[![Build Status](https://jenkins1.ugent.be/job/vsc_ldap/badge/icon)](https://jenkins1.ugent.be/job/vsc_ldap/)

This repository is part of the VSC tools, which are common tools used within our
organization.

Originally created by the HPC team of Ghent University (http://ugent.be/hpc).


# Namespaces and tools

## vsc
Common namespace used by all our python modules.

### ldap Collection of utilities to ease interaction with the LDAP servers.
Examples of the schema's used can be provided, although we do not include them
by default.
- __filter.py__: Construction of LDAP filters that can be combined in intuitive
  ways using well-known operators, such as __and__, __or__, and __not__.
- __group.py__: A group in LDAP, based on the posixGroup object class --
  extended with several fields. Has one or more members and at least one
  moderator.
- __project.py__: Projects that are run on the HPC infrastructure. These are
  autogroups, meaning their member list is built automagically.
- __user__.py: A user in LDAP.
- __utils.py__: Low-level LDAP utilities, such as making (and maintaining) a
  bind the the LDAP server. Higher level utilities for querying LDAP and the
  base class for entitites in LDAP.
- __vo.py__: A virtual organisation is a special kind of group.

# License
vsc-ldap is made available under the GNU General Public License (GPL) version 2.

# Acknowledgements
vsc-ldap was created with support of [Ghent University](http://www.ugent.be/en),
the [Flemish Supercomputer Centre (VSC)](https://vscentrum.be/nl/en),
the [Hercules foundation and the Department of Economy](http://www.herculesstichting.be/in_English),
and [the Department of Economy, Science and Innovation (EWI)](http://www.ewi-vlaanderen.be/en).
