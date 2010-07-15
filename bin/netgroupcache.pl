#!/usr/bin/perl
#

#This code pulls a copy of netgroups from the LDAP server, prefixes their name with 'local'
#and places them in the /etc/netgroups file
#
#by doing this, you can configure access.conf to also allow these local netgroups. thus
#allowing login even if the LDAP server is not online to answer netgroup queries. 
#
#This script should be run from cron at an appropriate interval.
#
#Usage:
#
#netgroupcache.pl <netgroup> <netgroup> <netgroup> .....
#
#\* may be used as a wildcard, including as the only argument
#to get all netgroups.
#
#(you can add as many netgroups as you like)

#This code uses the reference module for OSS directory actions:
#"OSS::LDAPops." Please see OSS/LDAPops.pm for details on the implemention
#of methods. 
#

#use strict pragma.
use strict;

#Use OSS::LDAPops object. 
use OSS::LDAPops;

#Load config
require '/etc/netgroupcache.conf';


#Instantiate new object. 
my($ldapopsobj) = OSS::LDAPops->new($GLOBAL::config);
if (ref($ldapopsobj) !~ m/OSS::LDAPops/ ) {die("Error instantiating object: $ldapopsobj")}; 
my($ret);
my(@retu);

#Get netgroup entries
sub get_entries
{
	my(@out);
	my($ngref);
	$ldapopsobj->bind;
	foreach my $netgroup (@ARGV)
	{
		@retu = $ldapopsobj->searchnetgroup($netgroup);
		die($retu[0]) if (($retu[0] ne undef) and (ref($retu[0]) !~ m/Net::LDAP::Entry/) );
		foreach my $entry (@retu) 
		{
			$ngref = $entry->get_value('nisNetgroupTriple', asref => 1);
			foreach my $ngt (@$ngref)
			{
				push(@out, 'local'.$entry->get_value('cn').' '.$ngt."\n"); 
			};
		};
	};
	return(@out);
};

#Write output to /etc/netgroup
sub write_output
{
	my(@file) = @_;
	open(FILE, '>'.'/etc/netgroup') or die($!);
	print(FILE @file);
	close(@file);

};

&write_output(&get_entries);
