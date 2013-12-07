#!/usr/bin/python
# -*- coding: Utf8 -*-
import sys
import logging

from fmatoolbox import DefaultCommand, DefaultCompleter
from core import *


# ---------------------------------------------------------------------------------------------------------------------
# User classes
# ---------------------------------------------------------------------------------------------------------------------
class ListUserCommand(AddLdapEntryCommand):
	"""Class designed to list users from the ldap directory"""

	
	def __call__(self, args):
		super(ListUserCommand, self).__call__(args)
		# TODO
		print "command : " + str(self.__class__.__name__)
		return False
		self.log.debug(str(self.__class__))

		dn = Dn()
		dn.addEntriesFromDnFragment(self.config.user.branch)
		dn.addEntriesFromDnFragment(self.ldap_suffix)

		scope = ldap.SCOPE_ONELEVEL
		attrlist = ["uid", "cn" ,] 
		r = self.ldap.search_s(dn.toString(), scope, attrlist = attrlist )
		print "Existing users : "
		for d,entry in r:
			uid = entry.get("uid")[0]
			displayName = entry.get("cn")[0]
			print " - " + str(displayName) + "\t\t( " + uid + " )"
		print "."

# ---------------------------------------------------------------------------------------------------------------------
# User sub parser
# ---------------------------------------------------------------------------------------------------------------------
def add_user_parser(subparsers, config, command_name, command_desc):

    parser_tmp = subparsers.add_parser(command_name, help=command_desc)
    subparsers2 = parser_tmp.add_subparsers()
    
    parser_tmp2 = subparsers2.add_parser('list',  help="List all existing users.")
    parser_tmp2.set_defaults(__func__=ListUserCommand(config))

# ---------------------------------------------------------------------------------------------------------------------
# Team classes
# ---------------------------------------------------------------------------------------------------------------------
class ListTeamCommand(DefaultCommand):

	def __call__(self, args):
		super(ListTeamCommand, self).__call__(args)
		print "command : " + str(self.__class__.__name__)


# ---------------------------------------------------------------------------------------------------------------------
# Team sub parser
# ---------------------------------------------------------------------------------------------------------------------
def add_team_parser(subparsers, config, command_name, command_desc):

	# this field is required, so it will contain at least one element
	host_types = config.host.type.value

	parser_tmp = subparsers.add_parser(command_name, help=command_desc)
	parser_tmp.add_argument('--host-type', choices = host_types , type=str, default=host_types[0])
	subparsers2 = parser_tmp.add_subparsers()
    
	parser_tmp2 = subparsers2.add_parser('list',  help="List all existing teams in the service zone")
	parser_tmp2.set_defaults(__func__=ListTeamCommand(config))

	#parser_tmp2 = subparsers2.add_parser('add', help="Add a team")
	#parser_tmp2.add_argument('--name', type=str, required=True  , help="The team name.")
	#parser_tmp2.set_defaults(__func__=NotImplementedYet())
	#
	#parser_tmp2 = subparsers2.add_parser('del', help="Delete a team")
	#parser_tmp2.add_argument('--name', type=str , help="Client name.")
	#parser_tmp2.set_defaults(__func__=NotImplementedYet())



# ---------------------------------------------------------------------------------------------------------------------
# Client classes
# ---------------------------------------------------------------------------------------------------------------------
class ListClientCommand(DefaultCommand):

	def __call__(self, args):
		super(ListClientCommand, self).__call__(args)
		print "command : " + str(self.__class__.__name__)


# ---------------------------------------------------------------------------------------------------------------------
# Client sub parser
# ---------------------------------------------------------------------------------------------------------------------
def add_client_parser(subparsers, config, command_name, command_desc):

	# this field is required, so it will contain at least one element
	host_types = config.host.type.value

	parser_tmp = subparsers.add_parser(command_name, help=command_desc)
	parser_tmp.add_argument('--host-type', choices = host_types , type=str, default=host_types[0])
	subparsers2 = parser_tmp.add_subparsers()
    

	parser_tmp2 = subparsers2.add_parser('list', help="List all clients.")
	parser_tmp2.set_defaults(__func__=ListClientCommand(config))
	
	parser_tmp2 = subparsers2.add_parser('add', help="Add a new client. Two entries are created, one for the service zone, an other in the host branch in order to contains all virtual machines dedicted to this client.")
	parser_tmp2.add_argument('--name', type=str, required=True  , help="The client name.")
	parser_tmp2.set_defaults(__func__=AddClientCommand(config))
	
	parser_tmp2 = subparsers2.add_parser('del', help="Delete a client")
	parser_tmp2.add_argument('--name', type=str , help="Client name.")
	parser_tmp2.set_defaults(__func__=RemoveClientCommand(config))
	
	
	
