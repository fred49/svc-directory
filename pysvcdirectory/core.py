#!/usr/bin/python
# -*- coding: Utf8 -*-
import sys , os
import ldap
import logging
import shlex
import subprocess
import hashlib
from base64 import encodestring as encode
from fmatoolbox import DefaultCommand

# ---------------------------------------------------------------------------------------------------------------------
class LdapEntry(object):
	def __init__(self, attr, value):
		self.attr = attr
		self.value = value

	def __repr__(self):
		""" display custom : instead of memory address and object type, we return a tuple"""
		return str( (self.attr, self.value, ) )

	def __str__(self):
		return self.attr + "=" + self.value

	def clone(self):
		return LdapEntry(self.attr, self.value)


# ---------------------------------------------------------------------------------------------------------------------
class Dn(object):
	def __init__(self, fqdn = None, suffix_len = 2):
		self.entries = []
		self.log = logging.getLogger("svc-directory")
		if fqdn :
			self.log.debug("fqdn: " + fqdn)
			exploded_fqdn = fqdn.split(".")
			
			for i in exploded_fqdn[:-suffix_len] :
				self.entries.append(LdapEntry("ou",i))

			for i in exploded_fqdn[-suffix_len:] :
				self.entries.append(LdapEntry("dc",i))

	def toString(self):
		res = []
		for entry in self.entries:
			res.append(str(entry))
		return ",".join(res)

	def clone(self):
		dn = Dn()
		for entry in self.entries:
			dn.entries.append(entry.clone())
		return dn


	def __repr__(self):
		""" display custom : instead of memory address and object type, we return a list"""
		return str( self.entries )


	def removeFirstEntry(self):
		self.entries = self.entries[1:]

	def insertLdapEntry(self, index, entry):
		self.entries.insert(index, entry)

	def addLdapEntry(self, entry):
		self.entries.append(entry)

	def addPrefixFromDnFragment(self, prefix, suffix_size = 2):
		# save suffix
		suffix = self.entries[-suffix_size:]
		# remove suffix from entries
		self.entries = self.entries[:-suffix_size] 
		# append prefix
		self.addEntriesFromDnFragment(prefix)
		# append saved suffix
		self.entries += suffix


	def changeSuffixFromDnFragment(self, suffix, suffix_size = 2):
		self.log.debug("suffix: " + str(suffix))
		# remove suffix:
		self.entries = self.entries[:-suffix_size]
		# add new suffix	
		self.addEntriesFromDnFragment(suffix)


	def addEntriesFromFqdnFragment(self, entries):
		# split entries 
		exploded_entries = entries.split(".")
		# add entries	
		for i in exploded_entries :
			self.entries.append(LdapEntry("ou",i))


	def addEntriesFromDnFragment(self, entries):
		# split entries 
		exploded_entries = entries.split(",")
		# add entries	
		for j in exploded_entries :
			a,b = j.split("=")
			self.entries.append(LdapEntry(a,b))


	def addSuffixFromFqdnFragment(self, suffix):
		# split suffix
		exploded_suffix = suffix.split(".")
		# add suffix	
		for i in exploded_suffix :
			self.entries.append(LdapEntry("dc",i))


# ---------------------------------------------------------------------------------------------------------------------
class AddLdapEntryCommand(DefaultCommand):

	def __init__(self, config):
		self.ldap = None
		self.log = logging.getLogger("svc-directory")
		self.config = config
                self.protected_args = [ 'password' ]

	def __call__(self, args):
		super(AddLdapEntryCommand, self).__call__(args)
		self.ldap_suffix = args.suffix
		self.verbose = args.verbose
		self.debug = args.debug
		self.bind(args.host, args.port, args.account, args.password, args.trace_level)

	def bind(self, host, port, account, pwd, trace_level):
		try:
			
			if self.verbose :
				self.log.info("Binding to host " + host + ", port " + port + ", account " + account)
			self.ldap = ldap.initialize( "ldap://%s:%s" % ( host, port )  , trace_level)
			self.ldap.simple_bind_s ( account, pwd )
		except ldap.INVALID_CREDENTIALS, e:
			self.log.error("Impossible de se connecter au serveur ldap://%s:%s avec le DN %s" % ( host, port , account ))
			sys.exit(1)

		except ldap.SERVER_DOWN, e:
			self.log.error("Impossible de se connecter au serveur %s:%s : serveur injoignable" % ( host, port ))
			sys.exit(1)

	def unbind(self):
		self.ldap.unbind()

	def ldap_add_ou(self, dn):
		# Check if the path to this entry exists.
		code , newdn = self.canCreateEntry(dn)
		if not code :
			self.log.error("Can not create the following entry '" + dn.toString() + "'. The closest existing element is : '" + newdn.toString() +"'") 
			sys.exit(1)	


		self.ldap.add_s(dn.toString(), [ ('objectclass' , ['top','organizationalUnit'] ), ] )

	def isExistingDn(self, dn):
		self.log.debug("dn is : " + dn.toString())
		try:
			r = self.ldap.search_s(dn.toString(), ldap.SCOPE_ONELEVEL, attrlist=['dn'])
			return True
		except ldap.NO_SUCH_OBJECT:
			self.log.debug("no such object : " + dn.toString())
		return False


	def canCreateEntry(self, dn):
		self.log.debug("dn is : " + dn.toString())
		dn = dn.clone()
		try:
			dn.removeFirstEntry()
			if len(dn.entries) > 2:
				r = self.ldap.search_s(dn.toString(), ldap.SCOPE_ONELEVEL, attrlist=['dn'])
				return (True, dn)
		except ldap.NO_SUCH_OBJECT:
			self.log.debug("no such object : " +dn.toString())
			code , new_dn= self._canCreateEntry(dn)
			return (False, new_dn)

		return (False, dn)


	def _canCreateEntry(self, dn):
		try:
			dn.removeFirstEntry()
			if len(dn.entries) > 2:
				r = self.ldap.search_s(dn.toString(), ldap.SCOPE_ONELEVEL, attrlist=['dn'])
				return (True, dn)
			else:
				return (False, dn)
		except ldap.NO_SUCH_OBJECT:
			self.log.debug("no such object : " +dn.toString())
			return self._canCreateEntry(dn)


	def listAllSubRdnEntry(self, dn, attr = 'ou' , filterstr ='(objectClass=*)', scope = ldap.SCOPE_ONELEVEL ):
		self.log.debug("dn is : " + dn.toString())
		self.log.debug("attr is : " + attr)
		self.log.debug("filterstr is : " +  filterstr)
		res = []
		try:
			#r = self.ldap.search_s(dn.toString(), ldap.SCOPE_ONELEVEL, attrlist=[attr,], filterstr = filterstr )
			r = self.ldap.search_s(dn.toString(), scope, attrlist=[attr,], filterstr = filterstr )
#SCOPE_BASE
#SCOPE_ONELEVEL
#SCOPE_SUBTREE

			for d,entry in r:
				attr_values = entry.get(attr)
				if attr_values :
					for value in attr_values :
						res.append(value)
				#res.append(entry[attr][0])
				#print 'Processing',repr(d), "name is : ", entry['ou'][0]

		except ldap.NO_SUCH_OBJECT:
			self.log.debug("ldap.NO_SUCH_OBJECT")
			pass
		return res

	def addAdminLocalGroup(self, dn):
		dn = dn.clone()
		dn.insertLdapEntry(0, LdapEntry("cn", "admin-local"))
		entry = [ ('objectclass' , ['posixGroup','top'] ),
				('cn', [ 'admin-local' ] ) ,
				('gidNumber', [ self.config.host.admin_local_gid_number, ]),
				]
		self.ldap.add_s(dn.toString(), entry)
		self.log.debug("dn created : " + str(dn))


	def addSshUsersGroup(self, dn):
		dn = dn.clone()
		dn.insertLdapEntry(0, LdapEntry("cn", "ssh-users"))
		entry = [ ('objectclass' , ['posixGroup','top'] ),
				('cn', [ 'ssh-users' ] ) ,
				('gidNumber', [ self.config.host.ssh_users_gid_number, ]),
				]
		self.ldap.add_s(dn.toString(), entry)
		self.log.debug("dn created : " + str(dn))


	def addAlias(self, dn, name, dnAliasTo):
		dn = dn.clone()
		dn.insertLdapEntry(0, LdapEntry("cn", name))
		entry = [ ('objectclass' , ['alias', 'extensibleObject','top'] ),
				('cn', [ name ] ) ,
				('aliasedObjectName', [ dnAliasTo.toString(), ]),
				]
		self.log.debug("dn: " + dn.toString())
		self.log.debug("entry: " + str(entry))

		try:
			r = self.ldap.search_s(dnAliasTo.toString(), ldap.SCOPE_ONELEVEL, attrlist=['dn'])
		except ldap.NO_SUCH_OBJECT:
			self.log.error("The entry '" + str(dnAliasTo.toString()) + "' does not exist !" )
			sys.exit(1)
		except ldap.INVALID_DN_SYNTAX :
			self.log.error("Invalid syntax for dn : '" + str(dnAliasTo.toString()) )
			sys.exit(1)
		
		self.ldap.add_s(dn.toString(), entry)
		self.log.debug("dn created : " + str(dn))


	def isSameSuffix(self, fqdn, fqdn_suffix):
		chunk = fqdn[-len(fqdn_suffix):]
		if chunk != fqdn_suffix :
			self.log.error("your fqdn has the wrong suffix : '" + fqdn + "'. Expected suffix : '" + fqdn_suffix + "'")
			sys.exit(0)


	def addServer(self, host_dn, description, expirationDate, contact):
		entry = []
		entry.append( ('objectclass' , ['top', 'server' ] ) )

		if description :
			entry.append( ('description', [description, ]) )
		if expirationDate :
			entry.append( ('expirationTimestamp', [ str(expirationDate) + "+0100", ]) )
		if contact:
			entry.append( ('mail', contact ) )
		
		entry.append( ('lastUidNumber', self.config.host.host_gid_default) )

		self.ldap.add_s(host_dn.toString(), entry )


	def genDnAccount(self, fqdn, root_dn, ldap_suffix):
		account = Dn()
		account.addLdapEntry(LdapEntry("uid", fqdn ))
		account.addEntriesFromDnFragment(root_dn)
		account.addEntriesFromDnFragment(ldap_suffix)
		return account


	def addAccount(self, dn, fqdn, description):

		# Password generation
		plain_text_password , ciphered_password = self.genPassword()

		# we create the entry into ldap
		self.log.debug("add bind account:" + dn.toString())
		entry = []
		entry.append( ('objectclass' , ['account', 'top', 'simpleSecurityObject' ] ) )
		entry.append( ('description', [description, ]) )
		entry.append( ('userPassword', [ ciphered_password, ]) )
		
		self.log.info("adding account:" + fqdn + " with the password : '" + str(plain_text_password) + "'")
		self.ldap.add_s(dn.toString(), entry)


	def genPassword(self):
		args="/usr/bin/pwgen -s -y 15 1"
		command=shlex.split(args)
		dpkgProcess     = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr  = dpkgProcess.communicate()
                ret             = dpkgProcess.wait()
		if ret == 0 :
			password = stdout.strip('\n')
			salt = os.urandom(4)
			h = hashlib.sha1(password)
			h.update(salt)
			cpassword =  "{SSHA}" + encode(h.digest() + salt)[:-1]
			self.log.debug("cpassword = '" + str(cpassword) + "'")
			return (password, cpassword)

			
		else:
			print "ERRO:pwgen is not installed!"
			print stderr
			sys.exit(1)


	def addService(self, host_dn, description, contact):
		entry = []

		entry.append( ('objectclass' , ['top', 'service' ] ) )
		if description :
			entry.append( ('description', [description, ]) )
		if contact:
			entry.append( ('mail', contact ) )
	
		self.ldap.add_s(host_dn.toString(), entry )




	def buildServiceDn(self, fqdn, host):
		# check fqdn suffix 
		self.isSameSuffix(fqdn, host.fqdn_suffix)

		# create the inpput_dn for this service
		input_dn=Dn(fqdn)
		self.log.debug("input_dn:" + str(input_dn))

		# create the host_dn for this service from the fqdn
		host_dn=Dn(fqdn)
		host_dn.entries[0].attr = "svc"
		# remove the suffix created from fqdn with the ldap suffix
		host_dn.changeSuffixFromDnFragment(self.ldap_suffix, len(host.fqdn_suffix.split(".")))

		# add prefix : hosts branch
		host_dn.addPrefixFromDnFragment(host.zone)
		self.log.debug("host_dn:" + str(host_dn))
		return input_dn , host_dn




	def buildServerDn(self, fqdn , host ):

		# check fqdn suffix 
		self.isSameSuffix(fqdn, host.fqdn_suffix)

		# create the inpput_dn for this server
		input_dn=Dn(fqdn)
		self.log.debug("input_dn:" + str(input_dn))

		# create the host_dn for this server from the fqdn
		host_dn=Dn(fqdn)
		host_dn.entries[0].attr = "hn"

		# remove the suffix created from fqdn with the ldap suffix
		host_dn.changeSuffixFromDnFragment(self.ldap_suffix, len(host.fqdn_suffix.split(".")))
		# add prefix : hosts branch
		host_dn.addPrefixFromDnFragment(host.branch)

		self.log.debug("host_dn:" + str(host_dn))
		return input_dn , host_dn



	def getValidUid(self, uids):
		""" one query by uid"""
		dn = Dn()
		dn.addEntriesFromDnFragment(self.config.user.branch)
		dn.addEntriesFromDnFragment(self.ldap_suffix)

		uidList = []	
		for uid in uids :
			scope = ldap.SCOPE_ONELEVEL
			attrlist = ["uid" ,] 
			filterstr = "(uid=" + uid + ")"
			r = self.ldap.search_s(dn.toString(), scope, attrlist = attrlist , filterstr = filterstr )
			self.log.debug("result : " + str(r))
			if len(r) == 1 :
				uidList.append(uid)
			elif len(r) == 0 :
				self.log.warn("No user found with uid : " + uid)
			else:
				self.log.error("multipe result entries for uid : " + uid)

		self.log.debug("uid list : " + str(uidList))
		return uidList

	def getValidUid2(self, uids):
		"""just one query to get all uids"""
		dn = Dn()
		dn.addEntriesFromDnFragment(self.config.user.branch)
		dn.addEntriesFromDnFragment(self.ldap_suffix)

		scope = ldap.SCOPE_ONELEVEL
		attrlist = ["uid" ,] 
		r = self.ldap.search_s(dn.toString(), scope, attrlist = attrlist)
		self.log.debug("result : " + str(r))
		ref = []
		for dn, attrs in r :
			ref.append( attrs['uid'][0])
		
		uidList = []	
		for uid in uids :
			if uid in ref :
				uidList.append(uid)
		self.log.debug("uid list : " + str(uidList))
		return uidList


	def addMembers(self, host_dn , uids):
		""" get just member attributes from entry"""

		if not self.isExistingDn(host_dn) :	
			self.log.error("The current entry '" + host_dn.toString() + "' does not exist")
			sys.exit(1)

		uidList = self.getValidUid(uids)
		if len(uidList) == 0 :
			self.log.warn("No valid uid(s) found. Operation aborted.")
			return

		scope = ldap.SCOPE_BASE
		old_entries  = self.ldap.search_s(host_dn.toString() , scope , attrlist=["memberUid",])
		self.log.debug("old_entries : " +str(old_entries))

		old_entry = old_entries[0][1]	

		if not old_entry.get('memberUid', None) :
			old_entry['memberUid'] = []

		members = []
		for i in uidList :
			if i not in old_entry['memberUid'] :
				members.append(i)

		self.log.debug("New members : " + str(members))

		if len(members) == 0 :
			self.log.warn("No new member(s) ! Operation aborted.")
			return

		# f MOD_ADD, MOD_DELETE, or MOD_REPLACE)
		# [(1, 'memberUid', None), (0, 'memberUid', ['uid', 'uid', 'uid'])]
		t =  [ (ldap.MOD_ADD, 'memberUid', members ),  ]
		self.log.debug("ldap operation : " + str(t))
		
		self.ldap.modify_s(host_dn.toString(), t )
		return members


	def removeMembers(self, host_dn , uids):
		""" get just member attributes from entry"""

		if not self.isExistingDn(host_dn) :	
			self.log.error("The current entry '" + host_dn.toString() + "' does not exist")
			sys.exit(1)

		scope = ldap.SCOPE_BASE
		old_entries  = self.ldap.search_s(host_dn.toString() , scope , attrlist=["memberUid",])
		self.log.debug("old_entries : " +str(old_entries))

		old_entry = old_entries[0][1]	

		members = []
		for i in uids :
			if i in old_entry['memberUid'] :
				members.append(i)
			else:
				self.log.warn("the current uid '" + i + "' was not found in the target")
				


		if len(members) == 0 :
			self.log.warn("No member(s) to remove ! Operation aborted.")
			return

		# f MOD_ADD, MOD_DELETE, or MOD_REPLACE)
		# [(1, 'memberUid', None), (0, 'memberUid', ['uid', 'uid', 'uid'])]
		t =  [ (ldap.MOD_DELETE, 'memberUid', members),  ]
		self.log.debug("ldap operation : " + str(t))
		
		self.ldap.modify_s(host_dn.toString(), t )
		return members


	def addMemberVersion2(self, fqdn , host_dn , uids):
		""" draft: get the entire entry"""

		uidList = self.getValidUid(uids)
		if len(uidList) == 0 :
			self.log.error("No valid uid(s) found. Operation abort.")

		import ldap.modlist as modlist
		print host_dn.toString()	
		scope = ldap.SCOPE_BASE
		old_entries  = self.ldap.search_s(host_dn.toString() , scope )
		self.log.debug("old_entries : " +str(old_entries))
		old_entry = old_entries[0][1]	
		print "old_entry : "
		print old_entry
		print

		import copy
		new_entry = copy.deepcopy(old_entry)
		print "new_entry : "
		print new_entry
		print

		a = old_entry['memberUid']
		for i in uidList :
			if i not in a :
				new_entry['memberUid'].append(i)

		print "new_entry : "
		print new_entry
		print
		print "old_entry : "
		print old_entry
		print


		t = modlist.modifyModlist(old_entry, new_entry )
		print "t : "
		print t

		self.ldap.modify_s(host_dn.toString(), t )
		return 


	def _getCurrentUid(self, dn, attr):
		r = self.ldap.search_s(dn.toString(), ldap.SCOPE_BASE, attrlist=[attr,])
		self.log.debug("current entry  : " + str(r))
		if len(r) <= 0 :
			self.log.error("can't find entry  : " + str(dn.toString()))
			sys.exit(1)
		entry = r[0][1]
		self.log.debug("current entry  : " + str(entry))
		if len(entry) <= 0:
			self.log.error("current entry is empty : " + str(entry))
			sys.exit(1)
		cpt = int(entry[attr][0])
		return cpt


	def _getCurrentUidOrCreate(self, dn, attr, default_value ):
		try:
			return 	self._getCurrentUid(dn, attr)
		except ldap.NO_SUCH_OBJECT:
			entry = []
			entry.append( ('objectclass' , ['top', 'uidSequence' ] ) )
			entry.append( (attr, default_value) )

			self.log.debug("dn : " + dn.toString())
			self.log.debug("adding entry : " + str(entry))
			self.ldap.add_s(dn.toString(), entry )

		try:
			return 	self._getCurrentUid(dn, attr)
		except ldap.NO_SUCH_OBJECT:
			self.log.error("ldap operation failed : NO_SUCH_OBJECT " + str(dn))
			sys.exit(1)



	def _increaseUid(self, dn, attr, cpt):

		mod = []
		mod.append( (ldap.MOD_DELETE, attr, str(cpt) ) )
		mod.append( (ldap.MOD_ADD, attr, str(cpt + 1) ) )

		self.log.debug("ldap operation : " + str(mod))
		try:	
			self.ldap.modify_s(dn.toString(), mod )
		except ldap.NO_SUCH_ATTRIBUTE:
			try:	
				self.ldap.modify_s(dn.toString(), mod )
			except ldap.NO_SUCH_ATTRIBUTE:
				self.log.error("ldap operation failed : NO_SUCH_ATTRIBUTE : " + str(mod))
				self.log.error("current gid sequence could be in use !!!")
				sys.exit(1)

		return cpt + 1


	def nextGid(self, dn_frag, default):
		dn = Dn()
		dn.addEntriesFromDnFragment(dn_frag)
		dn.addEntriesFromDnFragment(self.ldap_suffix)

		attr = "lastUidNumber"
		cpt = self._getCurrentUidOrCreate(dn, attr, default)
		return str(self._increaseUid(dn, attr, cpt))


	def deleteDn(self, dn):
		# Check if the current dn is existing
		self.log.debug("removing dn : " + dn.toString())
		if self.isExistingDn(dn) :	
			res = self.ldap.delete_s(dn.toString())
			self.log.debug("dn removed. (res=" + str(res) + ")")
			return True
		return False


	def deleteDnRecursively(self, dn):
	
		if self.isExistingDn(dn) :	

			scope = ldap.SCOPE_SUBTREE
			attrlist = ["dn",] 
			r = self.ldap.search_s(dn.toString(), scope, attrlist = attrlist )
			r.reverse()
			ret = False
			for dn, entry in r :
				self.log.debug("removing dn : " + dn)
				res = self.ldap.delete_s(dn)
				self.log.debug("dn removed. (res=" + str(res) + ")")
				ret = True
			return ret

	
	def addGroup(self, dn, name , gid):
		dn = dn.clone()
		dn.insertLdapEntry(0, LdapEntry("cn", str(name)))


		if self.isExistingDn(dn) :
			self.log.error("The group '" + dn.toString() + " is already existing.")
			sys.exit(1)
	

		entry = [ ('objectclass' , ['posixGroup','top'] ),
				('gidNumber', [ gid , ]),
				]

				#('cn', [ str(name) ] ) ,
		self.log.debug("dn : " + dn.toString())

		self.ldap.add_s(dn.toString(), entry)
		self.log.debug("dn created : " + str(dn))


	def addHostGroup(self, host_dn, name):

		attr = "lastUidNumber"
		cpt = self._getCurrentUid(host_dn, attr)
		gid = str(self._increaseUid(host_dn, attr, cpt))

		self.addGroup(host_dn, name , gid)


	def removeHostGroup(self, host_dn, name):

		dn = host_dn.clone()
		dn.insertLdapEntry(0, LdapEntry("cn", str(name)))

		if self.deleteDnRecursively(dn) :
			self.log.info("Group " + name + " was removed.")



# ---------------------------------------------------------------------------------------------------------------------
class NotImplementedYet(AddLdapEntryCommand):
	"""Class designed to list services"""


	def __call__(self, args):
		super(NotImplementedYet, self).__call__(args)
		self.log.debug(str(self.__class__))
		self.log.warn("NotImplementedYet ! ")


