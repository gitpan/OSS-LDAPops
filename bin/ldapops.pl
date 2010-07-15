#!/usr/bin/perl
#
#Perform operations on the OSS ldap directory

#This code uses the reference module for OSS directory actions:
#"OSS::LDAPops." Please see OSS/LDAPops.pm for details on the implemention
#of methods. 
#
#This program will return nothing on sucess and will die with
#an error message to STDERR on fail. 
#
#All operations required to administer the directory are avaliable
#via this program apart from changing objects outside of the user and group
#space. These must be altered manually. 
#
#This code does not have to run on the LDAP server as it is networm enabled
#and can be used over the network from a suitable location, ACL permitting of course!

#use strict pragma.
use strict;

#Use OSS::LDAPops object. 
use OSS::LDAPops;

#Global config
#These options are passed to OSS::LDAPops and are all required.
my($config) = 
{
	LDAPHOST	=>	'127.0.0.1',
	BINDDN		=>	'uid=webportal, ou=writeaccess, dc=auth, dc=lastminute,dc=com',
	BASEDN		=> 	'dc=auth,dc=lastminute,dc=com',
	NISDOMAIN	=>	'auth.lastminute.com',
	PASSWORD	=>	'test',
};

#These config options are used within this script
my($localconfig) =
{
	SHADOWMAX	=>	90,
	SHADOWMIN	=>	10,
	SHADOWWARNING	=>	10,
	SHELL		=>	'/bin/bash',
	#Trailing '/' please!
	HOMEPREFIX	=>	'/opt/userhomes/'
};


#Instantiate new object. 
my($ldapopsobj) = OSS::LDAPops->new($config);
if (ref($ldapopsobj) !~ m/OSS::LDAPops/ ) {die("Error instantiating object: $ldapopsobj")}; 
my($ret);
my(@retu);
#If argument x received....
#Search for user
if ($ARGV[0] eq '-su')
{
	if (!$ARGV[1]) 
	{
		print("\nUsage: ldaops.pl -su <search string>\n");
		exit;
	};
	$ldapopsobj->bind;
	@retu = $ldapopsobj->searchuser($ARGV[1]);
	die($retu[0]) if (($retu[0] ne undef) and (ref($retu[0]) !~ m/Net::LDAP::Entry/) );
	foreach my $entry (@retu) {$entry->dump; }
	#if($ret) {die($ret);};
	exit;
}
#Search for group 
elsif ($ARGV[0] eq '-sg')
{
	if (!$ARGV[1]) 
	{
		print("\nUsage: ldaops.pl -sg <search string>\n");
		exit;
	};
	$ldapopsobj->bind;
	@retu = $ldapopsobj->searchnetgroup($ARGV[1]);
	die($retu[0]) if (($retu[0] ne undef) and (ref($retu[0]) !~ m/Net::LDAP::Entry/) );
	foreach my $entry (@retu) {$entry->dump; }
	exit;
}
#Add host user group
elsif ($ARGV[0] eq '-ah')
{
	if (!$ARGV[1])
	{
		print("\nUsage: ldapops.pl -ah <hostname>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->addhost($ARGV[1]);
	if($ret) {die($ret);};
	exit;
}
#Add host group
elsif ($ARGV[0] eq '-ahg')
{
	if (!$ARGV[1])
	{
		print("\nUsage: ldapops.pl -ahg <group>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->addhostgroup($ARGV[1]);
	if($ret) {die($ret);};
	exit;
}
#Add user group
elsif ($ARGV[0] eq '-aug')
{
	if (!$ARGV[1])
	{
		print("\nUsage: ldapops.pl -aug <group>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->addusergroup($ARGV[1]);
	if($ret) {die($ret);};
	exit;
}
#Add user to user group
elsif ($ARGV[0] eq '-auug')
{
	if (!$ARGV[1]or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -auug <userid> <group>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->addusertoug($ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#Delete user from user group
elsif ($ARGV[0] eq '-duug')
{
	if (!$ARGV[1]or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -auug <userid> <group>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->deluserfromug($ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#Add host to host group
elsif ($ARGV[0] eq '-ahhg')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -ahhg <host> <group>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->addhosttohg($ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#Delete host from host group
elsif ($ARGV[0] eq '-dhhg')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -ahhg <host> <group>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->delhostfromhg($ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#Add user group to user group
elsif ($ARGV[0] eq '-augug')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -augug <addgroup> <togroup>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->addgrouptogroup('ug',$ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#Del ug from ug
elsif ($ARGV[0] eq '-dugug')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -augug <delgroup> <fromgroup>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->delgroupfromgroup('ug',$ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#add hg to hg
elsif ($ARGV[0] eq '-ahghg')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -augug <addgroup> <togroup>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->addgrouptogroup('hg',$ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#Del hg from hg
elsif ($ARGV[0] eq '-dhghg')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -augug <delgroup> <fromgroup>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->delgroupfromgroup('hg',$ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#add user to host user group
elsif ($ARGV[0] eq '-auh')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -auh <userid> <host>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->addusertohug($ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#Delete user from host user group
elsif ($ARGV[0] eq '-duh')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -auh <userid> <host>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->deluserfromhug($ARGV[1],$ARGV[2]);
	if($ret) {die($ret);};
	exit;
}
#Update passworf for user
elsif ($ARGV[0] eq '-up')
{
	if (!$ARGV[1] or !$ARGV[2])
	{
		print("\nUsage: ldapops.pl -up <userid> <password>\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->updatepw($ARGV[1],$ARGV[2],0);
	if($ret) {die($ret);};
	exit;
}
#Update passworf for user and force reset on next login
elsif ($ARGV[0] eq '-upr')
{
        if (!$ARGV[1] or !$ARGV[2])
        {
                print("\nUsage: ldapops.pl -upr <userid> <password>\n");
                exit;
        };
        $ldapopsobj->bind;
        $ret = $ldapopsobj->updatepw($ARGV[1],$ARGV[2],1);
        if($ret) {die($ret);};
        exit;
}

#Add user
elsif ($ARGV[0] eq '-au')
{
	print("\nAdd User:\n\nUsername:");
	my($uid,$givenname,$sn,$mail,$pw,$cn,$gid,$homedir,$loginshell,$employeenumber);
	$uid = <STDIN>;
	chomp($uid);
	print("\nFirst name:");
	$givenname = <STDIN>;
	chomp($givenname);
	print("\nSurname:");
	$sn = <STDIN>;
	chomp($sn);
	print("\nEmail address:");
	$mail = <STDIN>;
	chomp($mail);
	print("\nSG Number:");
	$employeenumber = <STDIN>;
	chomp($employeenumber);
	print("\nPassword:");
	$pw = <STDIN>;
	chomp($pw);
	$cn = $givenname.' '.$sn;
	$ldapopsobj->bind;
	$gid = 300;
	$homedir = $$localconfig{HOMEPREFIX}.$uid;
	$loginshell = $$localconfig{SHELL};
	$ret = $ldapopsobj->adduser($uid,$givenname,$sn,$cn,$mail,$pw,$gid,$homedir,$loginshell,$$localconfig{SHADOWMAX},$$localconfig{SHADOWMIN},$$localconfig{SHADOWWARNING},$employeenumber);
	if($ret) {die($ret);};
	exit;
}
#Delete DN
elsif ($ARGV[0] eq '-d')
{	
	if (!$ARGV[1])
	{
		print("\nUsage: ldapops.pl -d \'<dn>\'\n");
		exit;
	};
	$ldapopsobj->bind;
	$ret = $ldapopsobj->deletedn($ARGV[1]);
	if($ret) {die($ret);};
}
else 
#Print usage information 
{
	print("\nUsage:\n\n./ldapops.pl -su <string>\t\t\t| search user\n");
	print("./ldapops.pl -sg <string>\t\t\t| search group\n");
	print("./ldapops.pl -ah <hostname>\t\t\t| add host\n");
	print("./ldapops.pl -ahg <group>\t\t\t| add hostgroup\n");
	print("./ldapops.pl -aug <user>\t\t\t| add usergroup\n");
	print("./ldapops.pl -auug <userid> <group>\t\t| add user to user group\n");
	print("./ldapops.pl -duug <userid> <group>\t\t| delete user from user group\n");
	print("./ldapops.pl -auh <userid> <host>\t\t| add user to host\n");
	print("./ldapops.pl -duh <userid> <host>\t\t| delete user from host\n");
	print("./ldapops.pl -ahhg <host> <group>\t\t| add host to host group\n");
	print("./ldapops.pl -dhhg <host> <group>\t\t| delete host from host group\n");
	print("./ldapops.pl -augug <addgroup> <togroup>\t| add user group to user group\n");
	print("./ldapops.pl -dugug <delgroup> <fromgroup>\t| delete user group from user group\n");
	print("./ldapops.pl -ahghg <addgroup> <togroup>\t| add host group to host group\n");
	print("./ldapops.pl -dhghg <delgroup> <fromgroup>\t| delete host group from host group\n");
	print("./ldapops.pl -au \t\t\t\t| add user\n");
	print("./ldapops.pl -up \t\t\t\t| update password for user\n");
	print("./ldapops.pl -upr \t\t\t\t| update password for user and force reset on next login\n");
	print("./ldapops.pl -d \'<dn>\'\t\t\t\t| delete dn (note the quotes)\n");
	print("\nNote: the wildcard \'*\' can be used, but must be escaped as \\*\n");

};
