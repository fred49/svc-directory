#!/usr/bin/python
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

# This file is part of svc-directory.
#
# svc-directory is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# svc-directory iis distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with LinShare user cli.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright 2013 Frédéric MARTIN
#
# Contributors list :
#
#  Frédéric MARTIN frederic.martin.fma@gmail.com
#


# ---------------------------------------------------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------------------------------------------------
import os , re , sys
import argparse
import logging
import logging.handlers

from fmatoolbox import Config , Element , SimpleSection , SubSection, ElementWithRelativeSubSection, DefaultProgram
from fmatoolbox import streamHandler , debug_logging_format
from fmatoolbox import Base64ElementHook, SectionHook , TestCommand

# ---------------------------------------------------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------------------------------------------------
g_log = logging.getLogger()
g_log.setLevel(logging.INFO)
# logger handlers
g_log.addHandler(streamHandler)
# debug mode
# if you need debug during class construction, file config loading, ...,  you need to modify the logger level here.
if False:
	g_log.setLevel(logging.DEBUG)
	streamHandler.setFormatter(debug_logging_format)


# ---------------------------------------------------------------------------------------------------------------------
# create global configuration
# ---------------------------------------------------------------------------------------------------------------------
config = Config("svc-directory", mandatory=True, desc= """Just a description for a sample program. This program supports argcomplete.
To enable it, run in bash terminal :
	eval "$(register-python-argcomplete svc-directory.py)"
""")

# default
default_section = config.get_default_section()
default_section.add_element(Element('debug',	e_type=int,	default=0, desc="""debug level : default : 0."""))

# ldap section
section_ldap = config.add_section(SimpleSection("ldap", required=True))
section_ldap.add_element(Element('host',	conf_required=True,	default = "192.168.1.1"))
section_ldap.add_element(Element('account',	conf_required=True))
section_ldap.add_element(Element('suffix',	conf_required=True))
section_ldap.add_element(Element('port',	conf_required=True,	e_type=int))
section_ldap.add_element(Element('password',	conf_required=True,	hidden=False, desc = "manager account password to ldap. Could be store in base64.",
					 hooks = [ Base64ElementHook( warning = True),] ))


# user section
section_user = config.add_section(SimpleSection("user", required=True))
section_user.add_element(Element('branch',	conf_required=True))


# hosts section
section_host = config.add_section(SimpleSection("host", required=True))
section_host.add_element_list( 
				['type', 'global_group', 'pam_accounts' , 'service_accounts' ],
				conf_required=True)

# ['admin_local_gid_number', 'ssh_users_gid_number', 'service_accounts_gid_number', 'host_gid_default' ]
section_host.add_element_list( 
				['admin_local_gid_number', 'ssh_users_gid_number','host_gid_default' ],
				e_type=int,
				conf_required=True)

# host section : type subsection
rss = SubSection(prefix="host", required=True)
rss.add_element_list(
			['branch', 'zone', 'fqdn_suffix', 'service_group', 'team_branch', 'team_group' , 'client_branch', 'client_zone', 'projet_group_gid_seq', 'host_group_gid_seq'] ,
			required=True)
rss.add_element_list(
			[ 'projet_group_gid_default', 'host_group_gid_default' ] ,
			e_type=int,
			required=True)

section_host.add_element(ElementWithRelativeSubSection('type', rss))





# loading default configuration
config.load(exit_on_failure = True)

# ---------------------------------------------------------------------------------------------------------------------
# arguments parser
# ---------------------------------------------------------------------------------------------------------------------
parser = config.get_parser()
parser.add_argument('-d',			action="count",		**config.default.debug.get_arg_parse_arguments())
parser.add_argument('-v', '--verbose',		action="store_true", default=False)
parser.add_argument('--version',		action="version", version="%(prog)s 0.1")

# reloading configuration with previous optional arguments (ex config file name from argv, ...)
config.reload()

# Adding all others parsers.
subparsers = parser.add_subparsers()
parser_tmp = subparsers.add_parser('test', help="This simple command print cli argv and configuration read form config file.")
parser_tmp.set_defaults(__func__=TestCommand(config))

# run
prog = DefaultProgram(parser , config)
if prog() :
	sys.exit(0)
else :
	sys.exit(1)
