#! /usr/bin/env python
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

# This file is part of svc-directory.
#
# svc-directory is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# svc-directory is distributed in the hope that it will be useful,
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


# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import os
import re
import sys
import argparse
import logging
import logging.handlers

from fmatoolbox import Config, Element, SimpleSection, SubSection
from fmatoolbox import ElementWithRelativeSubSection, DefaultProgram
from fmatoolbox import streamHandler, debug_logging_format
from fmatoolbox import Base64ElementHook, SectionHook, TestCommand

from pysvcdirectory import commands

# -----------------------------------------------------------------------------
# logs
# -----------------------------------------------------------------------------
g_log = logging.getLogger()
g_log.setLevel(logging.INFO)
# logger handlers
g_log.addHandler(streamHandler)
# debug mode
# if you need debug during class construction, file config loading, ...,
# you need to modify the logger level here.
if os.getenv('_SVC_DIRECTORY_DEBUG', False):
    g_log.setLevel(logging.DEBUG)
    streamHandler.setFormatter(debug_logging_format)


# -----------------------------------------------------------------------------
# create global configuration
# -----------------------------------------------------------------------------
config = Config("svc-directory", mandatory=True, desc="""
This program is designed to help you for server managment, service managment
 and permission managment using a Ldap directory.
It lets you create servers, services, groups, clients, projects

This program supports argcomplete. It is automatically enabled if argcomplete
 is installed (pip install argcomplete) and Bash version superior to 4.2.
 For prior version, enable it using this command :
        eval "$(register-python-argcomplete svc-directory.py)"
""")


# default
default_section = config.get_default_section()
default_section.add_element(
    Element(
        'debug',
        e_type=int,
        default=0,
        desc="""Debug level : default : 0."""))

# ldap section
section_ldap = config.add_section(SimpleSection("ldap", required=True))

section_ldap.add_element(
    Element(
        'host',
        conf_required=True,
        default="192.168.1.1",
        desc="Ldap host"))

section_ldap.add_element(
    Element(
        'port',
        conf_required=True,
        e_type=int,
        desc="Ldap port"))

section_ldap.add_element(
    Element(
        'account',
        conf_required=True,
        desc="Ldap account manager like cn=admin,..."))

section_ldap.add_element(
    Element(
        'password',
        conf_required=True,
        hidden=False,
        desc="Ldap account password . Could be store in base64.",
        hooks=[Base64ElementHook(warning=True), ]))

section_ldap.add_element(
    Element(
        'suffix',
        conf_required=True,
        desc=argparse.SUPPRESS))

section_ldap.add_element(
    Element(
        'trace_level', e_type=int, default=0,
        desc="""Debug trace for Ldap : 0(default), 1, 2"""))


# user section
section_user = config.add_section(SimpleSection("user", required=True))
section_user.add_element(Element('branch',      conf_required=True))


# hosts section
section_host = config.add_section(SimpleSection("host", required=True))
section_host.add_element_list(
    ['type', 'global_group', 'pam_accounts', 'service_accounts'],
    conf_required=True)

# ['admin_local_gid_number', 'ssh_users_gid_number',
# 'service_accounts_gid_number', 'host_gid_default' ]
section_host.add_element_list(
    ['admin_local_gid_number', 'ssh_users_gid_number', 'host_gid_default'],
    e_type=int,
    conf_required=True)

# host section : type subsection
rss = SubSection(prefix="host", required=True)
rss.add_element_list(
    ['branch', 'zone', 'fqdn_suffix', 'service_group', 'team_branch',
        'team_group', 'client_branch', 'client_zone', 'projet_group_gid_seq',
        'host_group_gid_seq'],
    required=True)
rss.add_element_list(
    ['projet_group_gid_default', 'host_group_gid_default'],
    e_type=int,
    required=True)

section_host.add_element(
    ElementWithRelativeSubSection('type', rss, conf_required=True))

# loading default configuration
config.load(exit_on_failure=True)

# -----------------------------------------------------------------------------
# arguments parser
# -----------------------------------------------------------------------------
parser = config.get_parser(formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument(
    '-d', action="count",
    **config.default.debug.get_arg_parse_arguments())
parser.add_argument('-v', '--verbose', action="store_true", default=False)
parser.add_argument('--version', action="version", version="%(prog)s 0.1")

# reloading configuration with previous optional arguments
# (ex config file name from argv, ...)
config.reload()

# Adding all others parsers.
parser.add_argument('--host', **config.ldap.host.get_arg_parse_arguments())
parser.add_argument('--port', **config.ldap.port.get_arg_parse_arguments())
parser.add_argument('--account', **config.ldap.account.get_arg_parse_arguments())
parser.add_argument('--password', **config.ldap.password.get_arg_parse_arguments())
parser.add_argument('--suffix', **config.ldap.suffix.get_arg_parse_arguments())
parser.add_argument(
    '--trace-level',
    **config.ldap.trace_level.get_arg_parse_arguments())


# Adding all others subparsers.
subparsers = parser.add_subparsers()
parser_tmp = subparsers.add_parser(
    'test',
    help=""""This simple command print cli argv and configuration read
    form config file.""")
parser_tmp.set_defaults(__func__=TestCommand(config))

# host_types = config.host.type.split()
# default_host_type = host_types[0]

#add_config_parser(subparsers, "config",
# "Config tools like autocomplete configuration or pref-file generation.",
# config)
commands.add_user_parser(subparsers, config, "users",  "User operations")
commands.add_team_parser(subparsers, config, "teams",  "Team operations")
commands.add_client_parser(subparsers, config, 'clients', "Client operations")

#project             Project operations
#project-g           Project group operations : TBD
#project-m           Project group member operations : TBD
#service             Service operations
#service-m           Service member operations
#server              Server operations
#server-g            Server group operations (and host-group)

# run
prog = DefaultProgram(parser, config)
if prog():
    sys.exit(0)
else:
    sys.exit(1)
