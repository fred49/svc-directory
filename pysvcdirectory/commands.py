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
class ListClientCommand(AddLdapEntryCommand):
	"""Class designed to list clients"""


	def __call__(self, args):
		super(ListClientCommand, self).__call__(args)
		self.log.debug(str(self.__class__))

		dn = Dn()
		dn.addEntriesFromDnFragment(self.config.getHostConfig(args.host_type).client_zone)
		dn.addEntriesFromDnFragment(self.ldap_suffix)

		res = self.listAllSubRdnEntry(dn)

		print "Existing clients : "
		for i in res:
			print i
		print "."


# ---------------------------------------------------------------------------------------------------------------------
class AddClientCommand(AddLdapEntryCommand):
	"""Class designed to add a new client to ldap directory"""


	def __call__(self, args):
		super(AddClientCommand, self).__call__(args)
		self.log.debug(str(self.__class__))
		self.log.debug("client name : " + args.name)
		self.run( self.config.getHostConfig(args.host_type) , args.name)


	def run(self, host, clientname):
		self.addServerBranch(host.client_branch, host.client_zone, clientname)


	def addServerBranch(self, host_branch, service_branch, clientname):

		host = Dn()
		host.addEntriesFromDnFragment("ou=" + clientname)
		host.addEntriesFromDnFragment(host_branch)
		host.addEntriesFromDnFragment(self.ldap_suffix)

		service = Dn()
		service.addEntriesFromDnFragment("ou=" + clientname)
		service.addEntriesFromDnFragment(service_branch)
		service.addEntriesFromDnFragment(self.ldap_suffix)


		if self.isExistingDn(host) :
			self.log.warn("Client '" + clientname + "' is already existing")
			return False

		if self.isExistingDn(service) :
			self.log.warn("Client '" + clientname + "' is already existing")
			return False

		self.ldap_add_ou(host)
		self.ldap_add_ou(service)
		self.log.info("Client '" + clientname + "' was created.")
		return True



# ---------------------------------------------------------------------------------------------------------------------
class RemoveClientCommand(AddLdapEntryCommand):
	"""Class designed to remove a client from ldap directory"""


	def __call__(self, args):
		super(RemoveClientCommand, self).__call__(args)
		self.log.debug(str(self.__class__))
		self.log.debug("client name : " + args.name)

		if query_yes_no("You are going to delete the client '" + args.name + "', are you sure ? ", default="no") :
			self.run( self.config.getHostConfig(args.host_type) , args.name)


	def run(self, host, clientname):
		self.addServerBranch(host.client_branch, host.client_zone, clientname)


	def addServerBranch(self, host_branch, service_branch, clientname):

		host = Dn()
		host.addEntriesFromDnFragment("ou=" + clientname)
		host.addEntriesFromDnFragment(host_branch)
		host.addEntriesFromDnFragment(self.ldap_suffix)

		service = Dn()
		service.addEntriesFromDnFragment("ou=" + clientname)
		service.addEntriesFromDnFragment(service_branch)
		service.addEntriesFromDnFragment(self.ldap_suffix)


		at_least_one = False
		if self.deleteDnRecursively(host) :
			self.log.info("Client servers were removed.")
			at_least_one = True

		if self.deleteDnRecursively(service):
			at_least_one = True
			self.log.info("Client projets were removed.")

		if not at_least_one :
			self.log.warn("Nothing to remove !")
		else:
			self.log.info("Client '" + clientname + "' was removed.")



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
