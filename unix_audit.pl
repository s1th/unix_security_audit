#!/usr/bin/perl
use strict;

my $os = $^O;
if ($os =~ /sunos/i) { $os = "solaris" }; #just in case

print "#===================================================================\n";
print "Detected OS: $os\n";
print "Start Time: ";
print `date`;
print "\n";
print "uname -a:\n";
print `uname -a`;
print "\n";
print "#===================================================================\n";
#Get the user account information.  This is is used in lot of tests so let's store it 
#in memory for easy reference
my %pwd;      #store passwords
my %dupid;    #located duplicate user ids
my %grp;      #figure out which account belong to the same groups
my %etc_grps; #holds groups defined in /etc/group
my @snmpd_file;
my @syslog_file;
my @sshd_file;
my @smb_file;

open IN, "/etc/passwd" or warn "Can't open the /etc/passwd file - are you root (or equiv)?\n";
while (<IN>)
{
	chomp;
	my($username, $password, $userid, $groupid, $userid_info, $home_dir, $shell) = split/:/;
	$pwd{$username}->{pwd} = $password;
	$pwd{$username}->{info} = $userid_info;
	$pwd{$username}->{userid} = $userid;
	$pwd{$username}->{home_dir} = $home_dir;
	
	$dupid{$userid}->{cnt}++;
	$grp{$groupid}->{$username}->{info} = $userid_info;
}
close IN;

#Get the groups information for a check performed later
open IN, "/etc/group" or warn "Can't open the /etc/group file - are you root (or equiv)?\n";
while (<IN>)
{
	chomp;
	my($group_name, $password, $groupid, $group_list) = split/:/;
	$etc_grps{$group_name} = 1;
}
close IN;

#Let's traverse the filesystem and find *interesting* files
open WW, ">ww.txt" or warn "can't open the world-writeable files file.\n";
open WWD, ">wwd.txt" or warn "can't open the world-writeable directories file.\n";
open UFP, ">ufp.txt" or warn "can't open the uneven file permissions file.\n";
open SUID, ">suid.txt" or warn "can't open the setuid file.\n";
open SGID, ">sgid.txt" or warn "can't open the setgid file.\n";
open SBIT, ">sbit.txt" or warn "can't open the sticky bit file.\n";
open NOWN, ">nown.txt" or warn "can't open the no owner file.\n";
open NGRP, ">ngrp.txt" or warn "can't open the no owner file.\n";
open PDIR, ">pdir.txt" or warn "can't open the public dirs file.\n";

my @dirs = ("/");
for my $dir (@dirs)
{
	if ($dir eq "/proc" || $dir eq "/sys" || $dir eq "/dev") { next; } #skip /proc - not real files, just poiners to os settings, etc.
	my @lines = `ls -lL "$dir"`;
	for my $line (@lines)
	{
		if ($line =~ /^total/) {next};
		chomp $line;
		my($perms,undef,$owner,$group,undef,undef,undef,undef,$file_or_dir) = split /\s+/, $line;
		my $dir_str = substr($perms,0,1);
		
		#perms
		my($char1) = substr($perms,0,1);
		my($own_r) = substr($perms,1,1);
		my($own_w) = substr($perms,2,1);
		my($own_x) = substr($perms,3,1);
		my($grp_r) = substr($perms,4,1);
		my($grp_w) = substr($perms,5,1);
		my($grp_x) = substr($perms,6,1);
		my($wrld_r) = substr($perms,7,1);
		my($wrld_w) = substr($perms,8,1);
		my($wrld_x) = substr($perms,9,1);

		#mode
		my $mode = (stat($dir . "/" . $file_or_dir))[2];
		$mode = sprintf("0%o", $mode & 07777);
		my($owner_p) = substr($mode,1,1);
		my($group_p) = substr($mode,2,1);
		my($world_p) = substr($mode,3,1);
			
		if ($dir_str eq "d")
		{
			#check 5: world-writeable directories
			if ($own_w eq "w" && $grp_w eq "w" && $wrld_w eq "w")
			{
				if ($dir eq "/")
				{
					print WWD "$dir" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
					#print WWD "$dir" . "$file_or_dir" . " : $perms ($owner_p" . $group_p . $world_p . ")\n";
				}
				else
				{
					print WWD "$dir/$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
					#print WWD "$dir/$file_or_dir : $perms ($owner_p" . $group_p . $world_p . ")\n";
				}
			}
			
			#check 9: check ownership of all public directories						
			if ($wrld_w eq "w" || $wrld_x eq "T")
			{
				#public dir - permissions of 002, 1000, or 1002
				if ($dir eq "/")
				{
					print PDIR "$dir" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";					
				}
				else
				{
					print PDIR "$dir/$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
				}
			}

			#add the dir to the @dirs array to be processed			
			if ($dir eq "/")
			{ 
				my $to_add = $dir . $file_or_dir;
				#print "adding: $to_add\n";
				push @dirs, "$dir" . "$file_or_dir";
			}
			else
			{
				#print "adding $dir/$file_or_dir\n";
				push @dirs, "$dir/$file_or_dir";
			}
		}
		else
		{
			#analyze the file					
			#check 1: uneven file permissions - does the owner has less rights than group/world?
			if ($owner_p < $group_p || $owner_p < $world_p)
			{
				print UFP "$dir" . "/" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
				#print UFP "$dir" . "/" . "$file_or_dir : $perms ($owner_p" . $group_p .$world_p . ")\n";
			}	
		
			#check 2: world writeable files
			if ($own_w eq "w" && $grp_w eq "w" && $wrld_w eq "w")
			{
				print WW "$dir" . "/" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
				#print WW "$dir" . "/" . "$file_or_dir : $perms ($owner_p" . $group_p . $world_p . ")\n";
			}

			#check 3: setuid files
			#SUID or setuid: change user ID on execution. If setuid bit is set, when the file will be executed 
			#by a user, the process will have the same rights as the owner of the file being executed.
			#
			#If set, then replaces "x" in the owner permissions to "s", if owner has execute permissions, or to "S" otherwise. Examples:
			#     -rws------ both owner execute and SUID are set
			#     -r-S------ SUID is set, but owner execute is not set
			if ($own_x eq "s" || $own_x eq "S")
			{
				print SUID "$dir" . "/" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
			}

			#check 4: setgid files
			#SGID or setgid: Change group ID on execution. Same as above, but inherits rights of the group of 
			#the owner of the file. For directories it also may mean that when a new file is created in the directory 
			#it will inherit the group of the directory (and not of the user who created the file).
			#
			#If set, then replaces "x" in the owner permissions to "s", if owner has execute permissions, or to "S" otherwise. Examples:
			#			-rws------ both owner execute and SUID are set
			#			-r-S------ SUID is set, but owner execute is not set
			if ($grp_x eq "s" || $grp_x eq "S")
			{
				print SGID "$dir" . "/" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
			}

			#check 6: sticky bit
			#It was used to trigger process to "stick" in memory after it is finished, now this usage is obsolete.
			#Currently its use is system dependant and it is mostly used to suppress deletion of the files that belong 
			#to other users in the folder where you have "write" access to.
			#
			#If set, then replaces "x" in the owner permissions to "s", if owner has execute permissions, or to "S" otherwise. Examples:
			#			-rws------ both owner execute and SUID are set
			#			-r-S------ SUID is set, but owner execute is not set 
			if ($wrld_x eq "t" || $wrld_x eq "T")
			{
				print SBIT "$dir" . "/" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
			}
			#print "$file -> $perms -> $mode -> own:$owner_p, grp:$group_p, wrld:$world_p\n";
			
			#check 7: no owner - a file that is owner by an account that no longer exists on the system
			unless ( exists $pwd{$owner} )
			{
				#the owner doesn't exist in /etc/passwd
				print NOWN "$dir" . "/" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
			}
			
			#check 8: no group - a file that has an invalide group (e.g. it was deleted from the system)
			unless ( exists $etc_grps{$group} )
			{
				print NGRP "$dir" . "/" . "$file_or_dir" . " |" . " ($owner_p" . $group_p . $world_p . ") $line\n";
			}
			
			#set certain file locations
			if ( $file_or_dir =~ /snmpd.conf/i )
			{
				if ($dir =~ /\/usr\/etc/i) { push @snmpd_file, "$dir/$file_or_dir"; }
			}
			elsif ( $file_or_dir =~ /syslog.conf/i )
			{
				if ($dir =~ /\/usr\/etc/i) { push @syslog_file, "$dir/$file_or_dir"; }
			}
			elsif ( $file_or_dir =~ /sshd_config/i )
			{
				if ($dir =~ /\/usr\/etc/i) { push @sshd_file, "$dir/$file_or_dir"; }
			}
			elsif ( $file_or_dir =~ /smb.conf/i )
			{
				if ($dir =~ /\/usr\/etc/i) { push @smb_file, "$dir/$file_or_dir"; }
			}
		}
	}
}
print "\n";

close WW;
close WWD;
close UFP;
close SUID;
close SGID;
close SBIT;
close NOWN;
close NGRP;
close PDIR;

#========================================================================================================================
# MAIN TESTING SECTION
#========================================================================================================================
print "#===========================================\n";
print "# V-756 | GEN000020 | SV-27039r1_rule\n";
print "#============================================\n";
if ( $os =~ /linux/i)
{
	print `cat /etc/inittab`;
}
elsif ( $os =~ /solaris/i )
{
	print `cat /etc/default/sulogin`;
}
elsif ($os =~ /aix/i)
{ 
	print "AIX has a chassis key that is used to prevent booting to single-user mode\n";
	print "without a password.  Confirm it is in the correct position and the key has\n";
	print "been removed.\n";
	print "\n";
	print "But also, i suppose...\n";
	print `cat /etc/security/passwd`;
}
print "\n";

print "#======================================\n";
print "# V-11940 | GEN000100 | SV-27052r1_rule\n";
print "#=======================================\n";
print ">>> Is this a supported release?\n";
if ( $os =~ /linux/i)
{
	#for now let's assume you're redhat
	print `cat /etc/redhat-release`;
}
elsif ( $os =~ /solaris/i )
{
	print `uname -a`;
}
elsif ($os =~ /aix/i)
{ 
	print `oslevel`;
}
print "\n";


print "#====================================\n";
print "# V-783 | GEN000120 | SV-27060r1_rule\n";
print "#====================================\n";
print ">>> Up-to-date on software, system security patches and updates?\n";
if ( $os =~ /linux/i)
{
	print `rpm -qa --last`;
}
elsif ( $os =~ /solaris/i )
{
	print `patchadd -p | grep patch`;
}
elsif ($os =~ /aix/i)
{
	print `/usr/sbin/instfix -c -i | cut -d":" -f1`;
}
print "\n";

print "#======================================\n";
print "# V-4301  | GEN000240 | SV-38666r1_rule\n";
print "# V-22297 | GEN000253 | SV-38667r1_rule\n";
print "# V-22296 | GEN000252 | SV-40384r1_rule\n";
print "# V-22295 | GEN000251 | SV-39093r1_rule\n";
print "# V-22294 | GEN000250 | SV-40383r1_rule\n";
print "# V-22292 | GEN000244 | SV-28718r1_rule\n";
print "# V-22291 | GEN000242 | SV-39092r1_rule\n";
print "#======================================\n";
if ($os =~ /linux/i)
{
	print ">>> Is NTP running?\n";
	print `ps -e | egrep "xntpd|ntpd"`;
	print "\n";
	
	print ">>> Is NTP scheduled to run?\n"; 
	print `grep ntpdate /var/spool/cron/*`;
	print `grep ntpdate /etc/cron.d/*`;
	print `grep ntpdate /etc/cron.daily/*`;
	print `grep ntpdate /etc/cron.hourly/*`;
	print `grep ntpdate /etc/cron.monthly/*`;
	print `grep ntpdate /etc/cron.weekly/*`;
	print "\n";

	print ">>> Contents of 'ntp.conf'\n";
	print `cat /etc/ntp.conf`;
	
	print ">>> Who owns the 'ntp.conf' file?\n";
	print `ls -l /etc/ntp.conf`;
	
	print ">>> Extended ACL?\n";
	print `aclget /etc/ntp.conf`;
	
}	
elsif ($os =~ /solaris/i)
{
	print ">>> Is NTP running?";
	print `ps -e | egrep "xntpd|ntpd"`;
	print "\n";

	print ">>> Is NTP scheduled to run?\n";
	print `grep ntpdate /var/spool/cron/crontabs/*`;
	print "\n";

	print ">>> Contents of 'ntp.conf'\n";
	print `cat /etc/ntp.conf`;
	
	print ">>> Who owns the 'ntp.conf' file?\n";
	print `ls -l /etc/ntp.conf`;
	
	print ">>> Extended ACL?\n";
	print `aclget /etc/ntp.conf`;
}
elsif ($os =~ /aix/i)
{
 	print ">>> Is NTP running?\n";
	print `ps -e | egrep "xntpd|ntpd"`;

	print ">>> Is NTP scheduled to run?\n";
	print `grep ntpdate /var/spool/cron/crontabs/*`;

	print ">>> Contents of 'ntp.conf'\n";
	print `cat /etc/ntp.conf`;
	
	print ">>> Who owns the 'ntp.conf' file?\n";
	print `ls -l /etc/ntp.conf`;
	
	print ">>> Extended ACL?\n";
	print `aclget /etc/ntp.conf`;
}
print "\n";

print "#======================================\n";
print "# V-22290 | GEN000241 | SV-39091r1_rule\n";
print "#======================================\n";
print ">>> Contents of /etc/crontab\n";
print `cat /etc/crontab`;
print "\n";

print "#===================================\n";
print "# V-760| GEN000280 | SV-38668r1_rule\n";
print "# V-765| GEN000440 | SV-38935r1_rule\n";
print "#===================================\n";
print ">>> Last logins\n";
if ($os =~ /linux/i)
{
	print `last -R`;
}
elsif ($os =~ /solaris/i )
{
	print `last`;
}
elsif ($os =~ /aix/i)
{
	print `last`;
	print "\n";
	print ">>> /etc/security/failedlogin\n";
	print `last -f /etc/security/failedlogin`;
	
}
print "\n";

print "#=======================================\n";
print "# V-4269  | GEN000290 | SV-38767r1_rule\n";
print "# V-22302 | GEN000585 | SV-38769r1_rule\n";
print "# V-773   | GEN000880 | SV-773r2_rule\n";
print "# V-22347 | GEN001470\n";
print "#\n";
print "# GEN000290-1, GEN000290-2, GEN000290-3,\n";
print "# GEN000290-4\n"; 
print "#=======================================\n";
print ">>> Contents of /etc/passwd\n";
print `cat /etc/passwd`;
print "\n\n";
print ">>> Contents of /etc/shadow\n";
print `cat /etc/shadow`;
print "\n\n";
print ">>> Is this system using password shadowing?\n";
print ">>> (if all user accounts have an 'x' in the password field\n";
print ">>>  of the /etc/passwd then it's shadowing)\n";
my $shadow_flag = 1; #let's assume yes
for my $user (sort keys %pwd)
{
	my $pwd = $pwd{$user}->{pwd};
	if ($pwd ne 'x') { $shadow_flag = 0; }
}

if ($shadow_flag)
{
	print "System is using password shadowing.\n";
}
else
{
	print "System is NOT using password shadowing.\n";
}
print "\n\n";

print ">>> Are there any duplicate user ids (0 is a real problem [it's root])?\n";
print ">>> If there are any listed, find those in the output of /etc/passwd\n";
for my $id (sort keys %dupid)
{
	if ($dupid{$id}->{cnt} > 1)
	{
		for my $user (sort keys %pwd)
		{
			if ( $pwd{$user}->{userid} == $id )
			{
				print "$id - $user | $pwd{$user}->{info}\n";
			}
		}
	}
}
print "\n\n";

print ">>> What users are grouped together?  Does this make sense?\n";
print ">>> This has an impact on permissions assigned throughout the system.\n";
my %groupmembers;
foreach my $user (sort keys %pwd)
{
	my $usergrouptext;
	my @grouplist;
	
	#solaris nuance
	if ($os =~ /solaris/i)
	{
		$usergrouptext = `id -a $user`;
		my ($text1,$text2) = split /groups=/, $usergrouptext;
		@grouplist = split /,/, $text2;
	}
	else
	{
		$usergrouptext = `id -Gn $user`;
		@grouplist = split(' ',$usergrouptext);
	}	
	
    foreach my $group (@grouplist)
    {
        $groupmembers{$group}->{$user} = 1;
    }
}

for my $group (sort keys %groupmembers)
{
	print "----- group: $group -----\n";
	for my $user ( sort keys %{ $groupmembers{$group} } )
	{
		print "$user - $pwd{$user}->{info}\n";
	}
	print "\n\n";
}
print "\n";

print "#=====================================\n";
print "# V-762 | GEN000320 | SV-27067r1_rule\n";
print "# V-899 | GEN001440\n";
print "#=====================================\n";
print ">>> Other UID stuff.\n";
if ($os =~ /linux/i)
{
	">>> pwck -r\n";
	print `pwck –r`;  #this doesn't seem to be working...why?
	print "\n";
	print `cut -d: -f3 /etc/passwd | uniq -d`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> logins -d\n";
	print `logins -d`;
	print "\n\n";
	print ">>> pwck\n";
	print `pwck -r`;
	
}
elsif ($os =~ /aix/i)
{
	print `usrck -n ALL`;
}
print "\n";

print "#======================================\n";
print "# V-11946 | GEN000340 | SV-38669r1_rule\n";
print "#======================================\n";
print ">>> UIDs 0-99 are reserved for system accounts.\n";
print ">>> Are all of the below accounts system related?\n";
for my $user (sort keys %pwd)
{
	my $userid = $pwd{$user}->{userid};
	if ($userid < 100)
	{
		print "$userid\t$user | $pwd{$user}->{info}\n";
	}
}
print "\n";

print "#====================================\n";
print "# V-780 | GEN000360 | SV-39094r1_rule\n";
print "#====================================\n";
print ">>> Group IDs 0-99 (0-499 for linux) are reserved for system groups.\n";
print ">>> Are these appropriate?\n";
if ($os =~ /linux/i)
{
	for my $gid (sort keys %grp)
	{
		if ($gid < 500) 
		{
			print "----- groupid: $gid -----\n";
			for my $user (sort keys %{ $grp{$gid} })
			{
				print "$user | $grp{$user}->{info}\n";
			}
		}
	}
	print "\n";
}
else
{
	for my $gid (sort keys %grp)
	{
		if ($gid < 11) 
		{
			print "----- groupid: $gid -----\n";
			for my $user (sort keys %{ $grp{$gid} })
			{
				print "$user | $grp{$user}->{info}\n";
			}
		}
	}
	print "\n";
}
print "\n";

print "#====================================\n";
print "# V-780 | GEN000360 | SV-39094r1_rule\n";
print "#====================================\n";
print ">>> All groups in /etc/passwd must be in /etc/group.\n";
print ">>> Here's /etc/group.\n";
print `cat /etc/group`;
# my %etc_grp;  #hold groups from /etc/group
# open IN, "/etc/group" or warn "Can't open the /etc/group file.\n";
# while (<IN>)
# {
	# chomp;
	# my($groupname, $password, $groupid, $group_list) = split/:/;
	# $etc_grp{$groupname}->{$groupid}->{users} = $group_list;
# }
# close IN;

# for my $id (sort keys %grp)
# {
	# unless (exists $etc_grp{$id})
	# {
		# print "$id - doesn't exist in /etc/group.\n";
	# }
# }

print "#=======================================\n";
print "# V-763   | GEN000400 | SV-38932r1_rule\n";
print "# V-24331 | GEN000402 | SV-38933r1_rule\n";
print "# V-23732 | GEN000410 | SV-38934r1_rule\n";
print "#=======================================\n";
print ">>> Login banner displayed?\n";
if ($os =~ /linux/i)
{
	print ">>> /etc/issue\n";
	print `cat /etc/issue`;
	print "\n";
	
	print ">>> /etc/motd\n";
	print `cat /etc/motd`;
	print "\n";
	
	print ">>> /etc/issue.net";
	print `cat /etc/issue.net`;
	print "\n";
	
	print ">>> /etc/X11/xdm/Xresources (if GUI is implemented)\n";
	print `cat /etc/X11/xdm/Xresources`;
	print "\n";
	
	print ">>> /etc/X11/xdm/kdmrc (if GUI is implemented)\n";
	print `cat /etc/X11/xdm/kdmrc`;
	print "\n";
	
	print ">>> /etc/X11/gdm/gdm (if GUI is implemented)\n";
	print `cat /etc/X11/gdm/gdm`;
	print "\n";
	
	print ">>> /etc/vsftpd.conf\n";
	print `cat /etc/vsftpd.conf`;
	print "\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> /etc/issue\n";
	print `cat /etc/issue`;
	print "\n";

	print ">>> /etc/motd\n";
	print `cat /etc/motd`;
	print "\n";
	
	print ">>> /etc/dt/config/*/Xresources (if GUI is implemented)\n";
	print `cat /etc/dt/config/*/Xresources`;
	print "\n";
	
	print ">>> /etc/default/telnetd (if telnet is implemented without TCP_Wrappers)\n";
	print `cat /etc/default/telnetd`;
	print "\n";
	
	print ">>> /etc/default/ftpd (if ftp is implemented without TCP_Wrappers)\n";
	print `cat /etc/default/ftpd`; 	
	print "\n";
	
	print ">>> /etc/ftpd/banner.msg (Solaris 9 and above, if ftp is imp. wout TCP_Wrappers)\n";
	print `cat /etc/ftpd/banner.msg`; 	
	print "\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> /etc/motd\n";
	print `cat /etc/motd`;
	print "\n";
	
	print ">>> /etc/dt/config/*/Xresources (if GUI is implemented)\n";
	print `cat /etc/dt/config/*/Xresources`;
	print "\n";
	
	print ">>> /etc/ftpmotd\n";
	print `cat /etc/ftpmotd`;
	print "\n";
	
	print ">>> /etc/ftpaccess.ctl\n";
	print `cat /etc/ftpaccess.ctl`;
	print "\n";
	
	print ">>> /dev/console\n";
	print `cat /dev/console`;
	print "\n";
	
	print ">>> /etc/security/login.cfg\n";
	print `cat /etc/security/login.cfg`;
	print "\n";
}
print "\n";

print "#====================================\n";
print "# V-766 | GEN000460 | SV-38671r1_rule\n";
print "#\n";
print "# GEN000600-2, GEN000610\n";
print "#====================================\n";
if ($os =~ /linux/i)
{
	print ">>> Confirm 'account required /lib/security/pam_tally.so.deny=3 no_magic_root_reset'\n";
	print `cat /etc/pam.d/system-auth`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> Confirm LOCK_AFTER_RETRIES is set to YES in /etc/security/policy.conf\n";
    print `cat /etc/security/policy.conf`;
}
elsif ($os =~ /aix/i)
{
	print ">>> Confirm loginretries field is set to 3 or less, but not 0 for each user\n";
	print `cat /usr/sbin/lsuser -a loginretries ALL`;
}
print "\n";

print "#======================================\n";
print "# V-768   | GEN000480 | SV-38839r1_rule\n";
print "# V-22303 | GEN000590 | SV-38938r1_rule\n";
print "#======================================\n";
if ($os =~ /linux/i)
{
	print ">>> /etc/login.defs\n";
	print `cat /etc/login.defs`;
	print "\n";
	print ">>> Confirm FAIL_DELAY setting\n";
	print `grep FAIL_DELAY /etc/login.defs`;	
}
elsif ($os =~ /solaris/i )
{
	print ">>> /etc/default/login\n";
	print `cat /etc/default/login`;
	print "\n";
	print ">>> Confirm SLEEFTIME is set to 4 or more.\n";
	print `grp SLEEPTIME /etc/default/login`;
}
elsif ($os =~ /aix/i)
{
	print ">>> /etc/security/login.cfg\n";
	print `cat /etc/security/login.cfg`;
	print "\n";
	print ">>> Confirm 'logindelay' is set to 4 or more.\n";
	print `grep logindelay /etc/security/login.cfg`
}
print "\n";

print "#==================================\n";
print "# V-769 | GEN000520 | SV-769r2_rule\n";
print "#==================================\n";
print ">>> Output of ps -ef\n";
print `ps -ef`;
print "\n";

print "#======================================\n";
print "# V-1032  | GEN000540 | SV-38768r1_rule\n";
print "# V-11976 | GEN000700 | SV-38939r1_rule\n";
print "# V-22306 | GEN000750 | SV-38677r1_rule\n";
print "# V-22307 | GEN000790 | SV-38678r1_rule\n";
print "#======================================\n";
if ($os =~ /linux/i)
{
	print ">>> /etc/shadow - confirm mindays field (4th field, sep. by :) is set to 1 or more\n";
	print `cat /etc/shadow`;
	print "\n";
	print " >>> Use john the ripper to try to crack the password hashes in the second field\n";
	print " >>> of this file (sep. by :).  This is the best way to test the strength of the pwds.\n";
	print " >>> If the system doesn't use shadowing, then use the /etc/passwd output.\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> /etc/shadow - confirm mindays field (4th field, sep. by :) is set to 1 or more\n";
	print `cat /etc/shadow`;
	print "\n";
	print " >>> Use john the ripper to try to crack the password hashes in the second field\n";
	print " >>> of this file (sep. by :).  This is the best way to test the strength of the pwds.\n";
	print " >>> If the system doesn't use shadowing, then used the /etc/passwd output.\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> /etc/security/passwd\n";
	print `cat /etc/security/passwd`;
	print "\n";
	print " >>> Use john the ripper to try to crack the password hashes in the second field\n";
	print " >>> of this file (sep. by :).  This is the best way to test the strength of the pwds.\n";
	print " >>> If the system doesn't use shadowing, then used the /etc/passwd output.\n";
	print "\n";
	
	print ">>> Confirm minage field is set to 1 or more\n";
	print `/usr/sbin/lsuser -a minage ALL`;
	print "\n";
	
	print ">>> Confirm maxage field is set to policy\n";
	print `/usr/sbin/lsuser -a maxage ALL`;
	print "\n";
	
	print ">>> Confirm loginretries field is set to 3 or less, but not 0 for each user\n";
	print `cat /usr/sbin/lsuser -a loginretries ALL`;
	print "\n";
	
	print ">>> Confirm 'PASSLENGTH'\n";
	print `/usr/sbin/lsuser -a minlen ALL`;
	print "\n";
	
	print ">>> Confirm 'mindiff' setting - requires 4 chars be changed between old/new pwds\n";
	print `/usr/sbin/lsuser -a mindiff ALL`;
	print "\n";
}
print "\n";

print "#====================================\n";
print "# V-770 | GEN000560 | SV-27107r1_rule\n";
print "#====================================\n";
if ($os =~ /linux/i)
{
	print ">>> nullok exists?\n";
	print `grep nullok /etc/pam.d/system-auth`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> output of 'pwck'\n";
	print `pwck`;
}
elsif ($os =~ /aix/i)
{
	print ">>> pwdck -n ALL\n";
	print `pwdck -n ALL`;
}
print "\n";

print "#======================================\n";
print "# V-11947 | GEN000580 | SV-38936r1_rule\n";
print "#======================================\n";
if ($os =~ /linux/i)
{
	print ">>> Review 'pass_min_len'\n";
	print `grep minlen /etc/pam.d/passwd`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> Review 'PASSLENGTH'\n";
	print `grep PASSLENGTH /etc/default/passwd`;
}
elsif ($os =~ /aix/i)
{
	print ">>> Confirm 'PASSLENGTH'\n";
	print `/usr/sbin/lsuser -a minlen ALL`
}
print "\n";

print "#======================================\n";
print "# V-11973 | GEN000640 | SV-39503r1_rule\n";
print "#======================================\n";
if ($os =~ /linux/i)
{
	print ">>> ocredit - /etc/pam.d/passwd\n";
	print `grep ocredit /etc/pam.d/passwd`;
	print "\n";
	print ">>> ocredit - /etc/pam.d/system-auth\n";
	print `grep ocredit /etc/pam.d/system-auth`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> MINSPECIAL setting\n";
	print `grep MINSPECIAL /etc/default/passwd`;
}
elsif ($os =~ /aix/i)
{
	print ">>> This test is N/A.\n";
}
print "\n";

if ($os =~ /solaris/i )
{
	print "#======================================\n";
	print "# V-11975 | GEN000680 | SV-38675r1_rule\n";
	print "#======================================\n";
	print ">>> /etc/default/passwd\n";
	print `cat /etc/default/passwd`;
}
elsif ($os =~ /aix/i)
{
	print "#======================================\n";
	print "# V-11975 | GEN000680 | SV-38675r1_rule\n";
	print "#======================================\n";
	print ">>> /etc/security/user\n";
	print `cat /etc/security/user`;
}
print "\n";

print "#=====================================\n";
print "# V-4084 | GEN000800 | SV-38679r1_rule\n";
print "#=====================================\n";
if ($os =~ /linux/i)
{
	print ">>> Does the /etc/security/opasswd file exist (blank=no)?\n";
	print `ls /etc/security/opasswd`;
	print "\n";
	print ">>> Is the remember option set in /etc/pam.d/system-auth (blank=no)?\n";
	print `cat /etc/pam.d/system-auth | grep password | grep pam_unix.so | grep remember`;	
}
elsif ($os =~ /solaris/i )
{
	print ">>> grep HISTORY /etc/default/passwd\n";
	print `grep HISTORY /etc/default/passwd`
}
elsif ($os =~ /aix/i)
{
	print ">>> lsuser -a histsize ALL\n";
	print `lsuser -a histsize -ALL`;
}
print "\n";

print "#====================================\n";
print "# V-774 | GEN000900 | SV-38940r1_rule\n";
print "# V-775 | GEN000920 | SV-38941r1_rule\n";
print "#====================================\n";
print ">>> root's home directory\n";
print $pwd{'root'}->{home_dir};
print "\n";
print "\n";

print ">>> Permissions on root's home dir\n";
#print ">>> To calc the mode:\n";
#print ">>> Owner  Group  Other\n";
#print ">>> r w x  r w x  r w x\n";
#print ">>> 4 2 1  4 2 1  4 2 1\n";
#print ">>> ex. 0550 = Owner(r,x) - Group(r,x) - Other()\n";
my $root_hd = $pwd{'root'}->{home_dir};
print `ls -ld "$root_hd"`;

#my $mode = (stat($root_hd))[2];
#$mode = sprintf("0%o", $mode & 07777);
#print "$mode\n";
print "\n";

print "#======================================\n";
print "# V-776   | GEN000940 | SV-40085r1_rule\n";
print "# V-22310 | GEN000945 | SV-38770r1_rule\n";
print "# V-22311 | GEN000950 | SV-38772r1_rule\n";
print "#======================================\n";
print ">>> See PATH\n";
print `env`;
print "\n";

print "#==================================\n";
print "# V-777 | GEN000960 | SV-777r2_rule\n";
print "#==================================\n";
print ">>> Check for world-writeable files on dirs in root's PATH\n";
my $echo_PATH = `env | grep '^PATH'`;
my(undef,$PATH) = split /=/, $echo_PATH;
print "Root's PATH:\n";
print $PATH;

print ">>> See the world-writeable files section to find any files in these dirs.\n";
print ">>> V-1010 | GEN002480 | SV-1010r2_rule\n";
print "\n";

print "#=====================================\n";
print "# V-778 | GEN000980 | SV-38683r1_rule\n";
print "#=====================================\n";
print ">>> root console access\n";
if ($os =~ /linux/i)
{
	print ">>> /etc/securetty - make sure word 'console' exists\n";
	print `cat /etc/securetty`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> /etc/default/login - CONSOLE setting\n";
	print `grep CONSOLE=/dev/console /etc/default/login`;
}
elsif ($os =~ /aix/i)
{
	print `/user/sbin/lsuser -a rlogin root`;
}
print "\n";

print "#=====================================\n";
print "# V-4298 | GEN001000 | SV-27149r1_rule\n";
print "#=====================================\n";
if ($os =~ /linux/i)
{
	print ">>> Linux: see output above for V-778 | GEN000980 | SV-38683r1_rule\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> Confirm no output from 'consadm -p'\n";
	print `consadm -p`;
}
elsif ($os =~ /aix/i)
{
	print ">>> Ensure /etc/security/login.cfg does not define an alt console\n";
	print `cat /etc/security/login.cfg`
}
print "\n";

print "#======================================\n";
print "# V-11979 | GEN001020 | SV-40787r1_rule\n";
print "#======================================\n";
#############################
# Updated this section - test
#############################
if ($os =~ /solaris/i)
{
	print ">>> last root | grep -v reboot\n";
	print `last root | grep -v reboot`;
	print "\n\n";
	print ">>> egrep '^root:' /etc/user_attr\n";
	print `egrep '^root:' /etc/user_attr`;
	print "\n";
}
else
{
	print ">>> last root | grep -v reboot\n";
	print `last root | grep -v reboot`;
	print "\n\n";
}

print "#======================================\n";
print "# V-11980 | GEN001060 | SV-27154r1_rule\n";
print "#======================================\n";
if ($os =~ /linux/i)
{
	#######################################
	# Changed - test to see if it's working
	#######################################
	print ">>> /etc/syslog.conf (check config, are they logged to a remote system?)\n";
	print `cat /etc/syslog.conf`;
	print "\n\n";
	print ">>> Check possible default location: /var/log/messages\n";
	print `grep 'su.pam_unix' /var/log/messages`;	
	print "\n";	
}
elsif ($os =~ /solaris/i )
{
	print ">>> tail -10 /var/adm/sulog\n";
	print `tail -10 /var/adm/sulog`;
}
elsif ($os =~ /aix/i)
{
	print ">>> tail -10 /var/adm/sulog\n";
	print `tail -10 /var/adm/sulog`;
}
print "\n";

print "#=====================================\n";
print "# V-1046 | GEN001100 | SV-39097r1_rule\n";
print "#=====================================\n";
print ">>> Has root logged in over the network (not 'reboot' or 'console' in last logins)?\n";
print `last | grep "^root " | egrep -v "reboot|console"`;
print ">>> Check if secure shell is running - logging in over the network without it\n";
print ">>> is insecure and will transfer the password in clear text.\n";
print `ps -ef |grep sshd`;
print "\n";

print "#=====================================\n";
print "# V-1047 | GEN001120 | SV-38684r1_rule\n";
print "#=====================================\n";
##############################
## Updated this section - test
##############################
print `cat /etc/ssh/sshd_config`;
print "\n";

print "#==================================\n";
print "# V-784 | GEN001140 | SV-784r2_rule\n";
print "#==================================\n";
print ">>> This section of code checks for uneven file permissions.\n";
print ">>> Uneven file permissions are when the owner has less privileges\n";
print ">>> than the group or world users. The following locations will be checked:\n";
print ">>> /etc, /bin, /usr/bin, /usr/lbin, /usr/usb, /sbin, and /usr/sbin\n";
print ">>>\n";
print ">>> Note - this is done programmatically since the output of dumping\n";
print ">>> all files and their permissions would be too voluminous to go through\n";
print ">>> manually.\n";
open IN, "ufp.txt" or warn "Couldn't find the ufp.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("ufp.txt");
print "\n";

print "#====================================\n";
print "# V-785 | GEN001160 | SV-38942r1_rule\n";
print "#====================================\n";
print ">>> Find files with no owner (e.g. a user account that no longer exists).\n";
print ">>> This happens when a user creates/owns a file and the user is subsequently\n";
print ">>> removed from the system.  So, the user is no longer a valid account.\n";
open IN, "nown.txt" or warn "Couldn't find the nown.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("nown.txt");
print "\n";

print "#======================================\n";
print "# V-22312 | GEN001170 | SV-40084r1_rule\n";
print "#======================================\n";
print ">>> Find files without a valid group (e.g. a group that no longer exists).\n";
open IN, "ngrp.txt" or warn "Couldn't find the ngrp.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("ngrp.txt");
print "\n";

print "#==================================\n";
print "# V-901 | GEN001480 | SV-901r2_rule\n";
print "#==================================\n";
print ">>> Permissions on user's home directories\n";
for my $user (sort keys %pwd)
{
	my $home_dir = $pwd{$user}->{home_dir}; 
	my $line = `ls -ld "$home_dir"`;
	chomp $line;
	my($perms,undef,$owner,$group,undef,undef,undef,undef,$dir) = split /\s+/, $line;
	my $mode = (stat($home_dir))[2];
	$mode = sprintf("0%o", $mode & 07777);
	my($owner_p) = substr($mode,1,1);
	my($group_p) = substr($mode,2,1);
	my($world_p) = substr($mode,3,1);
	print "----- user: $user -----\n";
	print "home dir: $home_dir\n";
	print "\tpermissions: $perms\n";
	print "\tmode: $mode\n";
	print "\towner: $owner_p\n";
	print "\tgroup: $group_p\n";
	print "\tworld: $world_p\n";
	print "\n";
}
print "\n";


print "#======================================\n";
print "# V-907   | GEN001600 | SV-41074r1_rule\n";
print "# V-22354 | GEN001605 | SV-38879r1_rule\n";
print "# V-22355 | GEN001610 | SV-38881r1_rule\n";
print "#======================================\n";
print ">>> Run control scripts PATH variable - look for any . or ..\n";

##################################################
# Need to test this section
# *may need to escape the / in the commands below
##################################################
if ($os =~ /linux/i)
{
	print ">>> grep PATH /etc/rc* /etc/init.d\n";
	print `grep PATH /etc/rc* /etc/init.d`;
	print "\n\n";
	
	print ">>> grep -r LD_LIBRARY_PATH /etc/rc* /etc/init.d\n";
	print `grep -r LD_LIBRARY_PATH /etc/rc* /etc/init.d`;
	print "\n\n";
		
	print ">>> grep -r LD_PRELOAD /etc/rc* /etc/init.d\n";
	print `grep -r LD_PRELOAD /etc/rc* /etc/init.d`;
	print "\n";	
}
elsif ($os =~ /solaris/i )
{
	print ">>> find /etc/rc* /etc/init.d -type f -print | xargs grep -i PATH\n";
	print `find /etc/rc* /etc/init.d -type f -print | xargs grep -i PATH`;
	print "\n\n";
	
	print ">>> find /etc/rc* /etc/init.d -type f -print | xargs grep LD_LIBRARY_PATH\n";
	print `find /etc/rc* /etc/init.d -type f -print | xargs grep LD_LIBRARY_PATH`;
	print "\n\n";
	
	print ">>> find /etc/rc* /etc/init.d -type f -print | xargs grep LD_PRELOAD\n";
	print `find /etc/rc* /etc/init.d -type f -print | xargs grep LD_PRELOAD`;
	print "\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> grep -r PATH /etc/rc* /etc/init.d\n";
	print `grep -r PATH /etc/rc* /etc/init.d`;
	print "\n\n";
	print ">>> grep -r LIB /etc/rc* /etc/init.d\n";
	print `grep -r LIB /etc/rc* /etc/init.d`;
	print "\n\n";
	
	print ">>> grep -r LDR_PRELOAD /etc/rc* /etc/init.d\n";
	print `grep -r LDR_PRELOAD /etc/rc* /etc/init.d`;
	print "\n";
}
print "\n";

print "#====================================\n";
print "# V-916 | GEN002120 | SV-38741r1_rule\n";
print "#====================================\n";
if ($os =~ /aix/i)
{
	print ">>> /etc/security/login.cfg - check for 'shells' stanza\n";
	print `cat /etc/security/login.cfg`;
	print "\n\n";
	print ">>> /etc/shells\n";
	print `cat /etc/shells`;
	print "\n";
}
else
{
	print ">>> does /etc/shells file exist?\n";
	print `cat /etc/shells`;
	print "\n";
}
print "\n";

print "#======================================\n";
print "# V-805   | GEN002420 | SV-38746r1_rule\n";
print "# V-22368 | GEN002430 | SV-38747r1_rule\n";
print "#======================================\n";
##############################
###Updated this section - test
##############################
if ($os =~ /linux/i)
{
	print ">>> /etc/mtab\n";
	print `cat /etc/mtab`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> /etc/vfstab\n";
	print `cat /etc/vfstab`;
	print "\n\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> /etc/filesystems\n";
	print `cat /etc/filesystems`;
	print "\n\n";
	print ">>> output of lsfs\n";
	print `lsfs`;
	print "\n\n";
}
print "\n\n";



print "#====================================\n";
print "# V-802 | GEN002440 | SV-38945r1_rule\n";
print "# V-806 | GEN002500\n";
print "#====================================\n";
print ">>> All setgid files on the system\n";
open IN, "sgid.txt" or warn "Couldn't find the sgid.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("sgid.txt");
print "\n\n";


print ">>> All setuid files on the system\n";
open IN, "suid.txt" or warn "Couldn't find the suid.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("suid.txt");
print "\n\n";

print ">>> All files with sticky bit set on the system\n";
open IN, "sbit.txt" or warn "Couldn't find the sbit.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("sbit.txt");
print "\n";

print "#====================================\n";
print "# V-1010 | GEN002480 | SV-1010r2_rule\n";
print "#====================================\n";
print ">>> World-writeable directories\n";
open IN, "wwd.txt" or warn "Couldn't find the wwd.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("wwd.txt");
print "\n";

print "\n";
print ">>> World-writeable files\n";
open IN, "ww.txt" or warn "Couldn't find the ww.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("ww.txt");
print "\n";

print "#======================================\n";
print "# V-807   | GEN002520 | SV-807r2_rule\n";
print "# V-11990 | GEN002540 | SV-40066r1_rule\n";
print "#======================================\n";
print ">>> Public dirs ownership check.\n";
print ">>> Check 1: Are the above dirs owned by root?\n";
print ">>> Check 2: Are the above dirs group owned by root, sys, bin\n";
print ">>>          or some other application group?\n";
open IN, "pdir.txt" or warn "Couldn't find the pdir.txt file.\n";
while (<IN>)
{
	print $_;
}
close IN;
unlink ("pdir.txt");
print "\n";

print "#====================================\n";
print "# V-808 | GEN002560 | SV-39501r1_rule\n";
print "#====================================\n";
if ($os =~ /linux/i || $os =~ /solaris/i)
{
	print ">>> .:: Global level ::.\n";
	print ">>> Default umask 077 or less permissive?\n";
	print ">>> /etc/profile lines with umask in them\n";
	print `cat /etc/profile |grep umask`;
	print "\n";
	
	print "\n";
	print ">>> .:: Local level ::.\n";
	print ">>> User's can override this setting locally in their home dirs.  Check\n";
	print ">>> all user's home dirs for settings in .profile, .cshrc, .bash_profile,\n";
	print ">>> or .login files.  Not all of these may exist.\n";	
	for my $user (sort keys %pwd)
	{
		my $home_dir = $pwd{$user}->{home_dir};
		if ($home_dir eq "/proc" || $home_dir eq "/dev" || $home_dir eq "/") {next;}
		print "----- user: $user | home dir: $home_dir -----\n";
		print ">>> $home_dir/.profile";
		print `cat "$home_dir"/.profile | grep umask`;
		print "\n\n";
		print ">>> $home_dir/.cshrc";
		print `cat "$home_dir"/.cshrc | grep umask`;
		print "\n\n";
		print ">>> $home_dir/.bash_profile";
		print `cat "$home_dir"/.bash_profile | grep umask`;
		print "\n\n";
		print ">>> $home_dir/.login";
		print `cat "$home_dir"/.login | grep umask`;
		print "\n\n";
	}
}
elsif ($os =~ /aix/i)
{
	print ">>> Default umask 077 or less permissive?\n";
	print `/usr/sbin/lsuser -a umask ALL`;
}
print "\n";

print "#=====================================\n";
print "# V-810 | GEN002640 | SV-38897r1_rule\n";
print "#=====================================\n";
print ">>> Determine if default system accounts (e.g. sys, bin, uucp, nuucp, daemon,\n";
print ">>> smtp, etc.) have been disabled.\n";
print ">>> All locked accounts\n";
print ">>> See 'V-4269 | GEN000290' for `cat /etc/shadow`\n";
if ($os =~ /linux/i)
{
	print `awk -F: '\$2=="*" {print \$0}' /etc/shadow`;
}
elsif ($os =~ /solaris/i )
{
	print `grep "*LK*" /etc/shadow`;
}
elsif ($os =~ /aix/i)
{
	print `grep account_locked /etc/security/user`;
}
print "\n";

print "#====================================\n";
print "# V-811 | GEN002660 | SV-38946r1_rule\n";
print "#====================================\n";
print ">>> Auditing enabled?\n";
if ($os =~ /linux/i)
{
	print ">>> Is 'auditd' process running?\n";
	print `ps -ef | grep auditd`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> Is 'auditd' process running?\n";
	print `ps -ef | grep auditd`;
}
elsif ($os =~ /aix/i)
{
	print ">>> Are there entries in the audit log?  Let's see 1\n";
	print `/usr/sbin/audit query | head -1`;
}
print "\n";


print "#======================================\n";
print "# V-814   | GEN002720 | SV-38850r1_rule\n";
print "# V-815   | GEN002740 | SV-27294r1_rule\n";
print "# V-816   | GEN002760 | SV-40138r1_rule\n";
print "# V-818   | GEN002800 | SV-38856r1_rule\n";
print "# V-819   | GEN002820 | SV-38857r1_rule\n";
print "# V-22383 | GEN002825 | SV-38858r1_rule\n";
print "# V-29249 | GEN002760-10\n";
print "# V-29241 | GEN002760-2\n";
print "# V-29242 | GEN002760-3\n";
print "# V-29243 | GEN002760-4\n";
print "# V-29244 | GEN002760-5\n";
print "# V-29245 | GEN002760-6\n";
print "# V-29246 | GEN002760-7\n";
print "# V-29247 | GEN002760-8\n";
print "# V-29248 | GEN002760-9\n";
print "#\n";
print "# GEN002720-2, GEN002720-3, GEN002720-4\n";
print "# GEN002720-5, GEN002740-2\n";
print "#======================================\n";
if ($os =~ /linux/i)
{
	#using LAuS? (Linux audit subsystem)
	my $laus_file = "/etc/audit/filter.conf";
	my $file_loc1 = "/etc/audit.rules";
	my $file_loc2 = "/etc/audit/audit.rules";
	
	if (-e $laus_file)
	{
		#i guess so...
		print ">>> LAuS being used, here's /etc/audit/filter.conf\n";
		print `cat /etc/audit/filter.conf`;
		print "\n\n";
	}
	
	if (-e $file_loc1)
	{
		print ">>> /etc/audit.rules\n";
		print `cat /etc/audit.rules`;
		print "\n\n";
	}
	
	if (-e $file_loc2)
	{
		print ">>> /etc/audit/audit.rules\n";
		print `cat /etc/audit/audit.rules`;
		print "\n\n";
	}
}
elsif ($os =~ /solaris/i )
{
	print ">>> /etc/security/audit_control\n";
	print `cat /etc/security/audit_control`;
}
elsif ($os =~ /aix/i)
{
	print ">>> /etc/security/audit/events\n";
	print `cat /etc/security/audit/events`;
	print "\n\n";
	print ">>> /etc/security/audit/config\n";
	print `cat /etc/security/audit/config`;
}
print "\n\n";

print "#======================================\n";
print "# V-974   | GEN002960 | SV-27318r1_rule\n";
print "# V-11995 | GEN003060 | SV-27336r1_rule\n";
print "# V-982   | GEN003160 | SV-27350r1_rule\n";
print "# V-974   | GEN002960\n";
print "# V11995  | GEN003060\n";
print "#======================================\n";
print ">>> Wrath of Cron\n";
if ($os =~ /linux/i)
{
	#*** note this is flavor dependent - this is only coded for red hat, centos ***
	print ">>> ls -lL /etc/cron.allow\n";
	print `ls -lL /etc/cron.allow`;
	print "\n\n";
	print ">>> ls -lL /etc/cron.deny\n";
	print `ls -lL /etc/cron.deny`;
	print "\n\n";
	print ">>> /etc/cron.allow\n";
	print `cat /etc/cron.allow`;
	print "\n\n";
	print ">>> /etc/cron.deny\n";
	print `cat /etc/cron.deny`;
	print "\n\n";
	print ">>> /var/log/cron - first 10 entries\n";
	print `head -10 /var/log/cron`;
	print "\n\n";
	print ">>> grep cron /etc/syslog.conf\n";
	print `grep cron /etc/syslog.conf`;
	print "\n\n";
	print ">>> ls -lL /var/log/cron\n";
	print `ls -lL /var/log/cron`;
	print "\n\n";
	
}
elsif ($os =~ /solaris/i )
{
	print ">>> ls -lL /etc/cron.d/cron.allow\n";
	print `ls -lL /etc/cron.d/cron.allow`;
	print "\n\n";
	print ">>> ls -lL /etc/cron.d/cron.deny\n";
	print `ls -lL /etc/cron.d/cron.deny`;
	print "\n\n";
	print ">>> /etc/cron.d/cron.allow\n";
	print `cat /etc/cron.d/cron.allow`;
	print "\n\n";
	print ">>> /etc/cron.d/cron.deny\n";
	print `cat /etc/cron.d/cron.deny`;
	print "\n\n";
	print ">>> var/log/cron - first 10 entries\n";
	print `head -10 /var/log/cron`;
	print "\n\n";
	print ">>> Is CRONLOG set to YES?\n";
	print `cat /etc/default/cron | grep CRONLOG=YES`;
}
elsif ($os =~ /aix/i)
{
	print ">>> ls -lL /var/adm/cron/cron.allow\n";
	print `ls -lL /var/adm/cron/cron.allow`;
	print "\n\n";
	print ">>> ls -lL /var/adm/cron/cron.deny\n";
	print `ls -lL /var/adm/cron/cron.deny`;
	print "\n\n";
	print ">>> /var/adm/cron/cron.allow\n";
	print `cat /var/adm/cron/cron.allow`;
	print "\n";
	print ">>> /var/adm/cron/cron.deny\n";
	print `cat /var/adm/cron/cron.deny`;
	print "\n";
	print ">>> /var/adm/cron/log - first 10 entries\n";
	print `head -10 /var/adm/cron/log`;
}
print "\n";

print "#====================================\n";
print "# V-984 | GEN003280 | SV-27377r1_rule\n";
print "# V-985 | GEN003300 | SV-27381r1_rule\n";
print "# V-986 | GEN003320 | SV-27385r1_rule\n";
print "#====================================\n";
print ">>> Verify at.allow and at.deny\n";
if ($os =~ /linux/i)
{
	print ">>> /etc/at.allow\n";
	print `cat /etc/at.allow`;
	print "\n\n";
	print ">>> /etc/at.deny\n";
	print `cat /etc/at.deny`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> /etc/cron.d/at.allow\n";
	print `cat /etc/cron.d/at.allow`;
	print "\n\n";
	print ">>> /etc/cron.d/at.deny\n";
	print `cat /etc/cron.d/at.deny`;
}
elsif ($os =~ /aix/i)
{
	print ">>> /var/adm/cron/at.allow\n";
	print `cat /var/adm/cron/at.allow`;
	print "\n\n";
	print ">>> /var/adm/cron/at.deny\n";
	print `cat /var/adm/cron/at.deny`;
}
print "\n";


# ********************************************************
# ********************************************************
# ********************************************************
# ********************************************************
# ADDED AT WORK (FROM HERE BELOW)
# Need to test. - part of version 2
# ********************************************************
# ********************************************************
# ********************************************************
# ********************************************************

#========================
# Some AIX specific tests
#========================
if ($os =~ /aix/i)
{	
	print "#============================\n";
	print "# V-969 | GEN000000-AIX00020\n";
	print "# V-4287 | GEN000000-AIX00060\n";
	print "#============================\n";
	print ">>> Is the AIX trusted computing base (TCB) installed?\n";
	print ">>> attempting /bin/tcbck\n";
	print `/bin/tcbck`;
	print "\n";
	print ">>> attempting /usr/bin/tcbck\n";
	print `usr/bin/tcbck`;
}
print "\n";


if ($os =~ /aix/i)
{	
	print "#============================\n";
	print "# V-4284 | GEN000000-AIX00040\n";
	print "#============================\n";
	print ">>> 'securetcpip' command in /etc/security/config?\n";
	print `cat /etc/security/config`;
	print "\n";

	print "#=============================\n";
	print "# V-29496 | GEN000000-AIX00210\n";
	print "#=============================\n";
	print ">>> Does the system provide protection from ICMP attacks?\n";
	print ">>> Value of the 'tcp_icmpsecure' parameter (if this is not 1, then it's an issue)\n";
	print `/usr/sbin/no -o tcp_icmpsecure`;	
	print "\n";

	print "#=============================\n";
	print "# V-29497 | GEN000000-AIX00220\n";
	print "#=============================\n";
	print ">>> Does the system provide protection for the TCP stack against connection resets,\n";
	print ">>> SYN and data injection attacks?\n";
	print ">>> Value of the 'tcp_tcpsecure' parameter (if this is not 7, then it's an issue)\n";
	print `/usr/sbin/no -o tcp_tcpsecure`;	
	print "\n";

	print "#=============================\n";
	print "# V-29498 | GEN000000-AIX00230\n";
	print "#=============================\n";
	print ">>> Does the system provide protection against IP fragmentation attacks?\n";
	print ">>> Value of the 'tcp_tcpsecure' parameter (if this is less than 199, then it's an issue)\n";
	print `/usr/sbin/no -o ip_nfrag`;	
	print "\n";

	print "#=============================\n";
	print "# V-29499 | GEN000000-AIX00300\n";
	print "#=============================\n";
	print ">>> /etc/inetd.conf\n";
	print `cat /etc/inetd.conf`;	
	print "\n";
	print ">>> is the 'bootp' service active?  (if yes, it's an issue)\n";
	print `grep bootp /etc/inetd.conf`;
	print ">>> /etc/xinetd.conf\n";
	print `cat /etc/xinetd.conf`;
	print "\n";
	print ">>> is the 'bootp' service active? (if yes, it's an issue)\n";
	print `grep bootp /etc/xinetd.conf`;
	print "\n";
}

#Linux specific
if ($os =~ /linux/i)
{
	print "#==============================\n";
	print "# V-22349 | GEN000000-LNX001476\n";
	print "#==============================\n";
	print ">>> Does //etc/gshadow contain password hashes?\n";
	print ">>> /etc/gshadow\n";
	print `cat /etc/gshadow`;	
	print "\n";

	print "#============================\n";
	print "# V-4268 | GEN000000-LNX00320\n";
	print "#============================\n";
	print ">>> Any unnecessary special privilege accounts?\n";
	print ">>> shutdown, halt, or reboot?\n";
	print `grep "^shutdown" /etc/passwd`;
	print `grep "^halt" /etc/passwd`;
	print `grep "^reboot" /etc/passwd`;	
	print "\n";

	print "#============================\n";
	print "# V-1021 | GEN000000-LNX00360\n";
	print "# V-1022 | GEN000000-LNX00380\n";
	print "#============================\n";
	print ">>> ps -ef |grep X\n";	
	print `ps -ef|grep X`;	
	print "\n";

	print "#============================\n";
	print "# V-1025 | GEN000000-LNX00400\n";
	print "#============================\n";
	print ">>> /etc/security/access.conf\n";
	print `cat /etc/security/access.conf`;
	print "\n";
	print ">>> Permissions\n";
	print `ls -lL /etc/security/access.conf`;	
	print "\n";

	print "#============================\n";
	print "# V-4339 | GEN000000-LNX00560\n";
	print "#============================\n";
	print ">>> NFS server running?\n";
	print `ps -ef|grep nfsd`;
	print "\n";
	print ">>> exportfs -v (note - if nfs not running ignore this)\n";
	print ">>> Confirm the 'insecure_locks' option\n";
	print `exportfs -v`;	
	print "\n";
	
	print "#============================\n";
	print "# V-4346 | GEN000000-LNX00600\n";
	print "#============================\n";
	print ">>> pam_console.so module configured in any file in /etc/pam.d?\n";
	print `grep pam_console.so /etc/pam.d/*`;
	print "\n";
	print ">>> Does the /etc/security/console.perms file exist?\n";	
	print `ls -la /etc/security/console.perms`;	
	print "\n";
}

print "#=========================\n";
print "# V-4083 | GEN000500\n";
print "#\n";
print "# GEN000500-2, GEN000500-3\n";
print "#=========================\n";
print ">>> Inactivity\n";
if ($os =~ /linux/i)
{
	print ">>> Run gconftool-2 - 'idle_activation_enabled' (should return true)\n";
	print `gconftool-2 --direct --config-source xlm:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled`;
	print "\n";
	print ">>> Run gconftool-2 - idle_delay\n";
	print `gconftool-2 --direct --config-source xlm:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay`;
	print "\n";
	print ">>> Run gconftool-2 - lock_enabled\n";
	print `gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled`;
}
elsif ($os =~ /solaris/i )
{
	print `cat /etc/dt/config/C/sys.resource | grep -i dtsession | grep -i locktimeout`;
}
elsif ($os =~ /aix/i)
{
	print ">>> Have to do this manually.\n";
}
print "\n";

print "#====================\n";
print "# V-11948 | GEN000600\n";
print "# V-11972 | GEN000620\n";
print "# V-11973 | GEN000640\n";
print "# V-11975 | GEN000680\n";
print "# V-11976 | GEN000700\n";
print "# V-22306 | GEN000750\n";
print "# V-4084  | GEN000800\n";
print "#====================\n";
print ">>> Password character mix\n";
if ($os =~ /linux/i)
{
	print ">>> lcredit and ucredit should be set to -1\n";
	print `egrep "lcredit|ucredit" /etc/pam.d/system-auth`;
	print "\n";
	print ">>> dcredit - minimum digits setting should be >= 1\n";
	print `grep dcredit /etc/pam.d/system-auth`;
	print "\n";
	print ">>> ocredit should be set to -1\n";
	print ">>> check /etc/pam.d/passwd\n";
	print `grep ocredit /etc/pam.d/passwd`;
	print "\n";
	print ">>> check /etc/pam.d/system-auth\n";
	print `grep ocredit /etc/pam.d/system-auth`;
	print "\n";
	print ">>> Confirm max days field (5th field, sep by ':')\n";
	print `cat /etc/shadow`;
	print "\n";
	print ">>> /etc/pam.d/system-auth file (again)\n";
	print `cat /etc/pam.d/system-auth`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> Confirm MINLOWER and MINUPPER is set to at least 1\n";
	print `grep "MINLOWER|MINUPPER" /etc/default/passwd`;
	print "\n";
	print ">>> MINDIGIT should be greater than or equal to 1\n";
	print `grep MINDIGIT /etc/default/passwd`;
	print "\n";
	print ">>> MINSPECIAL is 1 or greater\n";
	print `grep MINSPECIAL /etc/default/passwd`;
	print "\n";
	print ">>> MAXREPEATS is set to less than 3\n";
	print `grep -i maxrepeats /etc/default/passwd`;
	print "\n";
	print ">>> Confirm the max days field (5th field sep by ':')\n";
	print `cat /etc/shadow`;
	print "\n";
	print ">>> Password reuse\n";
	print `grep HISTORY /etc/default/passwd`;
}
elsif ($os =~ /aix/i)
{
	print ">>> minalpha setting\n";
	print `grep minalpha /etc/security/user`;
	print "\n";
	print ">>> minother setting\n";
	print `grep minother /etc/security/user`;
	print "\n";
	print ">>> MAXREPEATS is set to less than 3\n";
	print `grep -i maxrepeats /etc/security/user`;
	print "\n";
	print ">>> Confirm the maxage field\n";
	print `/usr/sbin/lsuser -a maxage ALL`;
	print "\n";
	print ">>> 'mindiff' parameter\n";
	print `lsuser -a mindiff ALL`;
	print "\n";
	print ">>> Password reuse - 'histsize'\n";
	print `/usr/sbin/lsuser -a histsize ALL`;
}
print "\n";

# ********************************************************
# ********************************************************
# ********************************************************
# ********************************************************
# ADDED AT WORK (FROM HERE BELOW)
# Need to test. - part of version 3
# ********************************************************
# ********************************************************
# ********************************************************
# ********************************************************

print "#====================\n";
print "# V-22370 | GEN002715\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> ls -l /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd\n";
	print `ls -l /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> ls -l /usr/sbin/auditd /usr/sbin/audit /usr/sbin/bsmrecord /usr/sbin/auditreduce /usr/sbin/praudit /usr/sbin/auditconfig\n";
	print `ls -l /usr/sbin/auditd /usr/sbin/audit /usr/sbin/bsmrecord /usr/sbin/auditreduce /usr/sbin/praudit /usr/sbin/auditconfig`;
	print "\n\n";
}
elsif ($os =~ /aix/i)
{
	#no command for this?
}
print "\n";

print "#====================\n";
print "# V-22375 | GEN002730\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> cat /etc/audit/auditd.conf\n";
	print `cat /etc/audit/auditd.conf`;
	print "\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> grep audit_warn /etc/mail/aliases\n";
	print `grep audit_warn /etc/mail/aliases`;
	print "\n";
}
elsif ($os =~ /aix/i)
{
	#n/a
}
print "\n";

print "#=======================\n";
print "# V-22376 | GEN002750\n";
print "# V-22377 | GEN002751\n";
print "# V-22378 | GEN002752\n";
print "# V-22382 | GEN002753\n";
print "# V-816   | GEN002760\n";
print "# V-818   | GEN002800\n";
print "# V-819   | GEN002820\n";
print "# V-29272 | GEN002820-10\n";
print "# V-29274 | GEN002820-11\n";
print "# V-29275 | GEN002820-12\n";
print "# V-29279 | GEN002820-13\n";
print "# V-29250 | GEN002820-2\n";
print "# V-29251 | GEN002820-3\n";
print "# V-29252 | GEN002820-4\n";
print "# V-29253 | GEN002820-5\n";
print "# V-29255 | GEN002820-6\n";
print "# V-29257 | GEN002820-7\n";
print "# V-29259 | GEN002820-8\n";
print "# V-29261 | GEN002820-9\n";
print "# V-22383 | GEN002825\n";
print "# V-29281 | GEN002825-2\n";
print "# V-29284 | GEN002825-3\n";
print "# V-29286 | GEN002825-4\n";
print "# V-29288 | GEN002825-5\n";
print "#=======================\n";
if ($os =~ /linux/i)
{
	print ">>> auditctl -l |egrep '(useradd|groupadd)'\n";
	print `auditctl -l |egrep '(useradd|groupadd)'`;
	print "\n\n";
	print ">>> auditctl -l |egrep '(/etc/passwd|/etc/shadow|/etc/group/etc/gshadow)'\n";
	print `auditctl -l |egrep '(/etc/passwd|/etc/shadow|/etc/group/etc/gshadow)'`;
	print "\n\n";
	print ">>> auditctl -l |egrep '(usermod|groupmod)'\n";
	print `auditctl -l |egrep '(usermod|groupmod)'`;
	print "\n\n";
	print ">>> auditctl -l | grep /usr/bin/passwd\n";
	print `auditctl -l | grep /usr/bin/passwd`;
	print "\n\n";
	print ">>> auditctl -l | egrep '(userdel|groupdel)'\n";
	print `auditctl -l | egrep '(userdel|groupdel)'`;
	print "\n\n";
	print ">>> egrep \"faillog|lastlog\" /etc/audit/audit.rules\n";
	print `egrep "faillog|lastlog" /etc/audit/audit.rules`;
	print "\n\n";
	
	
	#dump the file again
	print ">>> cat /etc/audit/audit.rules\n";
	print `cat /etc/audit/audit.rules`;
	print "\n\n";
	
}
elsif ($os =~ /solaris/i )
{
	print ">>> cat /etc/security/audit_control\n";
	print `cat /etc/security/audit_control`;
	print "\n\n";
	print ">>> grep ua /etc/security/audit_control\n";
	print `grep ua /etc/security/audit_control`;
	print "\n\n";
	print ">>> grep flags /etc/security/audit_control\n";
	print `grep flags /etc/security/audit_control`;
	print "\n\n";
	print ">>> grep lo /etc/security/audit_control\n";
	print `grep lo /etc/security/audit_control`;
	print "\n\n";
	
}
elsif ($os =~ /aix/i)
{
	print ">>> cat /etc/security/audit/events\n";
	print `cat /etc/security/audit/events`;
	print "\n\n";
	print ">>> cat /etc/security/audit/config\n";
	print `cat /etc/security/audit/config`;
	print "\n\n";
}
print "\n";

print "#====================\n";
print "# V-24357 | GEN002870\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> grep \"audit\" /boot/grub/grub.conf\n";
	print `grep "audit" /boot/grub/grub.conf`;
	print "\n\n";
	print ">>> grep \"active\" /etc/audisp/plugins.d/syslog.conf\n";
	print `grep "active" /etc/audisp/plugins.d/syslog.conf`;
	print "\n\n";
	print ">>> audit records forwarded to remote server?\n";
	print `grep "\*.\*" /etc/syslog.conf|grep "@"`;
	print "\n";
	print "or\n";
	print `grep "\*.\*" /etc/rsyslog.conf| grep "@"`;
	print "\n\n";
	
}
elsif ($os =~ /solaris/i )
{
	print ">>> See the /etc/security/audit_control file\n";
	print ">>> Search: V-819 | GEN002820\n"; 
	print "\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> Consult with IT to see if remote logging is performed.\n";
}
print "\n";

print "#==================\n";
print "# V-988 | GEN003360\n";
print "# V-989 | GEN003380\n";
print "#==================\n";
if ($os =~ /linux/i)
{
	print ">>> ls -la /var/spool/at\n";
	print `ls -la /var/spool/at`;
	print "\n\n";
	print ">>> ls /var/spool/at (dirs) - cross ref against V-1010 | GEN002480\n";
	print `ls /var/spool/at`;
}
elsif ($os =~ /solaris/i )
{
	print ">>> ls -la /var/spool/cron/atjobs\n";
	print `ls -la /var/spool/cron/atjobs`;
	print "\n\n";
	print ">>> ls /var/spool/cron/atjobs (dirs) - cross ref against V-1010 | GEN002480\n";
	print `ls /var/spool/cron/atjobs`;
}
elsif ($os =~ /aix/i)
{
	print ">>> ls -la /var/spool/cron/atjobs /var/spool/atjobs\n";
	print `ls -la /var/spool/cron/atjobs /var/spool/atjobs`;
	print "\n\n";
	print "ls /var/spool/cron/atjobs /var/spool/atjobs (dirs) - cross ref against V-1010 | GEN002480\n";
	print `ls /var/spool/cron/atjobs /var/spool/atjobs`;
}
print "\n";

print "#=====================\n";
print "# V-22404 | GEN003510\n";
print "# V-11997 | GEN0003520\n";
print "#=====================\n";
if ($os =~ /linux/i)
{
	print ">>> service kdump status (verify it's not running)\n";
	print `service kdump status`;
	print "\n\n";
	print ">>> owner of the kernel core dump data directory\n";
	print `ls -ld /var/crash`;
	
}
elsif ($os =~ /solaris/i )
{
	print ">>> dumpadm | grep 'Savcore enabled' (verify Savecore is not used)\n";
	print `dumpadm | grep 'Savcore enabled'`;
	print "\n\n";
	print ">>> grep DUMPADM_ENABLE /etc/dumpadm.conf\n";
	print `grep DUMPADM_ENABLE /etc/dumpadm.conf`;
	print "\n\n";
	print ">>> owner of the kernel core dump data directory\n";
	print ">>> ls -ld /var/crash\n";
	print `ls -ld /var/crash`;
	print "\n\n";
	print ">>> grep DUMPADM_SAVDIR /etc/dumpadm.conf | cut-d= -f2 | ls -ld\n";
	my $dump_dir = `grep DUMPADM_SAVDIR /etc/dumpadm.conf | cut -d= -f2`;
	chomp $dump_dir;
	print `ls -ld "$dump_dir"`;
	print "\n\n";
	
}
elsif ($os =~ /aix/i)
{
	print ">>> sysdumpdev -l\n";
	print `sysdumpdev -l`;
	print "\n\n";
	print ">>> sysdumpdev -l | grep -i 'core dir' | ls -ld\n";
	print `sysdumpdev -l | grep -i 'core dir' | ls -ld`;
}
print "\n";

print "#====================\n";
print "# V-11999 | GEN003540\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> sysctl kernel.exec-shield\n";
	print `sysctl kernel.exec-shield`;
	print "\n\n";
	print ">>> sysctl kernel.randomize_va_space\n";
	print `sysctl kernel.randomize_va_space`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> /etc/system\n";
	print `cat /etc/system`;
}
elsif ($os =~ /aix/i)
{
	print ">>> Discuss with the system administrator.\n";
}
print "\n";

print "#====================\n";
print "# V-12002 | GEN003600\n";
print "# V-23741 | GEN003601\n";
print "# V-22409 | GEN003602\n";
print "# V-22410 | GEN003603\n";
print "# V-22411 | GEN003604\n";
print "# V-22412 | GEN003605\n";
print "# V-22413 | GEN003606\n";
print "# V-22414 | GEN003607\n";
print "# V-22416 | GEN003609\n";
print "# V-22417 | GEN003610\n";
print "# V-22419 | GEN003612\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> grep [01] /proc/sys/net/ipv4/conf/*/accept_source_route|egrep \"default|all\"\n";
	print `grep [01] /proc/sys/net/ipv4/conf/*/accept_source_route|egrep "default|all"`;
	print "\n\n";
	print ">>> cat /proc/sys/net/ipv4/tcp_max_syn_backlog\n";
	print `cat /proc/sys/net/ipv4/tcp_max_syn_backlog`;
	print "\n\n";
	print ">>> cat /etc/sysconfig/iptables\n";
	print `cat /etc/sysconfig/iptables`;
	print "\n\n";
	print ">>> cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts (should be 1)\n";
	print `cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts`;
	print "\n\n";
	print ">>> cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts (should be 1)\n";
	print `cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts`;
	print "\n\n";
	print "grep [01] /proc/sys/net/ipv4/conf/*/accept_source_route|egrep \"default|all\" (should all end in 0)\n";
	print `grep [01] /proc/sys/net/ipv4/conf/*/accept_source_route|egrep "default|all"`;
	print "\n\n";
	print ">>> grep [01] /proc/sys/net/ipv4/conf/*/accept_redirects|egrep \"default|all\" (should all end in 0)\n";
	print `grep [01] /proc/sys/net/ipv4/conf/*/accept_redirects|egrep "default|all"`;
	print "\n\n";
	print ">>> grep [01] /proc/sys/net/ipv4/conf/*/send_redirects|egrep \"default|all\" (should all end in 0)\n";
	print `grep [01] /proc/sys/net/ipv4/conf/*/send_redirects|egrep "default|all"`;
	print "\n\n";
	print ">>> cat /proc/sys/net/ipv4/tcp_syncookies (should be 1)\n";
	print `cat /proc/sys/net/ipv4/tcp_syncookies`;
	print "\n\n";	
}
elsif ($os =~ /solaris/i )
{
	print ">>> ndd /dev/ip ip_forward_src_routed\n";
	print `ndd /dev/ip ip_forward_src_routed`;
	print ">>> ndd /dev/tcp tcp_conn_req_max_q0\n";
	print "\n\n";
	print `ndd /dev/tcp tcp_conn_req_max_q0`;
	print "\n\n";
	print ">>> ndd /dev/ip ip_respond_to_timestamp\n";
	print `ndd /dev/ip ip_respond_to_timestamp`;
	print "\n\n";
	print ">>> ndd /dev/ip ip_respond_to_echo_broadcast (result should be 0)\n";
	print `ndd /dev/ip ip_respond_to_echo_broadcast`;
	print "\n\n";
	print ">>> ndd /dev/ip ip_respond_to_echo_broadcast (should be 0)\n";
	print `ndd /dev/ip ip_respond_to_echo_broadcast`;
	print "\n\n";
	print ">>> ndd /dev/tcp tcp_rev_src_routes (should be 0)\n";
	print `ndd /dev/tcp tcp_rev_src_routes`;
	print "\n\n";
	print ">>> ipfstat -o\n";
	print `ipfstat -o`;
	print "\n\n";
	print ">>> ipfstat -i\n";
	print `ipfstat -i`;
	print "\n\n";
	print ">>> ndd -get /dev/ip ip_ignore_redirect (should be 1)\n";
	print `ndd -get /dev/ip ip_ignore_redirect`;
	print "\n\n";
	print ">>> ndd /dev/ip ip_send_redirects (should be 0)\n";
	print `ndd /dev/ip ip_send_redirects`;
	print "\n\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> /usr/sbin/no -o ipsrcrouteforward\n";
	print `/usr/sbin/no -o ipsrcrouteforward`;
	print "\n";
	print ">>> /usr/sbin/no -o clean_partial_conns";
	print `/usr/sbin/no -o clean_partial_conns`;
	print "\n";
	print ">>> lsfit\n";
	print `lsfit`;
	print "\n\n";
	print ">>> /usr/sbin/no -o icmpaddressmask (should be 0)\n";
	print `/usr/sbin/no -o icmpaddressmask`;
	print "\n\n";
	print ">>> /usr/sbin/no -o bcastping (should be 0)\n";
	print `/usr/sbin/no -o bcastping`;
	print "\n\n";
	print ">>> /usr/sbin/no -p nolocsroute (should be 0)\n";
	print `/usr/sbin/no -p nolocsroute`;
	print "\n\n";
	print ">>> /usr/sbin/no -o ipsrcroutesend (should be 0)\n";
	print `/usr/sbin/no -o ipsrcroutesend`;
	print "\n\n";
	print ">>> /usr/sbin/no -o ipsrcrouterecv (should be 0)\n";
	print `/usr/sbin/no -o ipsrcrouterecv`;
	print "\n\n";
	print ">>> /usr/sbin/no -o ipignoreredirects (should be 1)\n";
	print `/usr/sbin/no -o ipignoreredirects`;
	print "\n\n";
	print ">>> /usr/sbin/no -o ipsendredirects (should be 0)\n";
	print `/usr/sbin/no -o ipsendredirects`;
	print "\n\n";
	print ">>> /usr/sbin/no -o clean_partial_conns (should be 1)\n";
	print `/usr/sbin/no -o clean_partial_conns`;
	print "\n\n";
}
print "\n";

print "#====================\n";
print "# V-12004 | GEN003660\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> grep \"authpriv.debug\" /etc/syslog.conf\n";
	print `grep "authpriv.debug" /etc/syslog.conf`;
	print "\n\n";
	print ">>> grep \"authpriv.info\" /etc/syslog.conf\n";
	print `grep "authpriv.info" /etc/syslog.conf`;
	print "\n\n";
	print ">>> grep \"authpriv\.\*\" /etc/syslog.conf\n";
	print `grep "authpriv\.\*" /etc/syslog.conf`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> grep \"auth.notice\" /etc/syslog.conf\n";
	print `grep "auth.notice" /etc/syslog.conf`;
	print "\n\n";
	print ">>> grep \"auth.info\" /etc/syslog.conf\n";
	print `grep "auth.info" /etc/syslog.conf`;
	print "\n\n";
	print ">>> grep 'auth.*' /etc/syslog.conf\n";
	print `grep 'auth.*' /etc/syslog.conf`;
	print "\n\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> grep \"auth.notice\" /etc/syslog.conf\n";
	print `grep "auth.notice" /etc/syslog.conf`;
	print "\n\n";
	print ">>> grep \"auth.info\" /etc/syslog.conf\n";
	print `grep "auth.info" /etc/syslog.conf`;
	print "\n\n";
	print `grep 'auth.*' /etc/syslog.conf`;
	print "\n\n";
}
print "\n";

print "#====================\n";
print "# V-12005 | GEN003700\n";
print "# V-1011  | GEN003800\n";
print "# V-4687  | GEN003820\n";
print "# V-22431 | GEN003825\n";
print "# V-22432 | GEN003830\n";
print "# V-22433 | GEN003835\n";
print "# V-4688  | GEN003840\n";
print "# V-22434 | GEN003845\n";
print "# V-24386 | GEN003850\n";
print "# V-4701  | GEN003860\n";
print "# V-845   | GEN004980\n";
print "# V-4696  | GEN005280\n";
print "# V-1026  | GEN006080\n";
print "# V-940   | GEN006580\n";
print "# V-29500 | GEN009140\n";
print "# V-29501 | GEN009160\n";
print "# V-29502 | GEN009180\n";
print "# V-29503 | GEN009190\n";
print "# V-29504 | GEN009200\n";
print "# V-29505 | GEN009210\n";
print "# V-29506 | GEN009220\n";
print "# V-29507 | GEN009230\n";
print "# V-29508 | GEN009240\n";
print "# V-29509 | GEN009250\n";
print "# V-29510 | GEN009260\n";
print "# V-29511 | GEN009270\n";
print "# V-29512 | GEN009280\n";
print "# V-29513 | GEN009290\n";
print "# V-29514 | GEN009300\n";
print "# V-29515 | GEN009310\n";
print "# V-29516 | GEN009320\n";
print "# V-29517 | GEN009330\n";
print "# V-29518 | GEN009340\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> ps -ef | grep xinetd\n";
	print `ps -ef | grep xinetd`;
	print "\n\n";
	print ">>> What are the active services running on the system?\n";
	print ">>> grep disable /etc/xinetd.d/* | grep no \n";
	print `grep disable /etc/xinetd.d/* | grep no`;
	print "\n\n";
	print ">>> cat /etc/xinetd.conf\n";
	print `cat /etc/xinetd.conf`;
	print "\n\n";
	print ">>> For xinetd each configuration file (per service) in the xinet.d\n";
	print ">>> directory contains additional settings.  Output each of those\n";
	print ">>> files below.\n";
	my @files = `ls /etc/xinetd.d`;
	my $path = "/etc/xinetd.d/";
	for my $file (@files)
	{
		chomp $file;
		my $full_path = $path . $file;
		print "----- file: $file -----\n";
		print `cat "$full_path"`;
		print "\n\n";
	}
	print "\n";
	print ">>> portmap service running?\n";
	print ">>> service portmap status\n";
	print `service portmap status`;
	print "\n\n";
	print ">>> portmap package installed?\n";
	print ">>> rpm -qa | grep portmap\n";
	print `rpm -qa | grep portmap`;
	print "\n\n";
	print ">>> rshd installed?\n";
	print ">>> rpm -qa | grep rsh-server\n";
	print `rpm -qa | grep rsh-server`;
	print "\n\n";
	print ">>> telnet running?\n";
	print ">>> ps -ef|grep telnetd\n";
	print `ps -ef|grep telnetd`;
	print "\n\n";
	print ">>> For the odd case where vsftp is not started by xinetd, output conf file.\n";
	print ">>> cat /etc/vsftpd/vsftpd.conf\n";
	print `cat /etc/vsftpd/vsftpd.conf`;
	print "\n\n";
	print ">>> uucp utility running?\n";
	print ">>> service uucp status\n";
	print `service uucp status`;
	print "\n\n";
	print ">>> SWAT used with SSL?\n";
	print ">>> grep -H \"bin/swat\" /etc/inetd.d/* | cut -d: -f1 | xargs grep \"only_from\"\n";
	print `grep -H "bin/swat" /etc/inetd.d/* | cut -d: -f1 | xargs grep "only_from"`;
	print "\n\n";
	print ">>> TCP_WRAPPERS installed?\n";
	print ">>> rpm -qa | grep tcp_wrappers\n";
	print `rpm -qa | grep tcp_wrappers`;
	print "\n\n";
	
	
}
elsif ($os =~ /solaris/i )
{
	print "inetd running?\n";
	print ">>> svcs -a | grep inetd\n";
	print `svcs -a | grep inetd`;
	print "\n\n";
	print ">>> What services are enabled?\n";
	print ">>> inetadm | grep -v disabled\n";
	print `inetadm | grep -v disabled`;
	print "\n\n";
	print ">>> The inet service properties for each of the enabled services\n";
	print ">>> inetadm | grep enabled | awk '{print \$NF}' | xargs inetadm -l\n";
	print `inetadm | grep enabled | awk '{print \$NF}' | xargs inetadm -l`;
	print "\n\n";
	print ">>> cat /etc/inetd.conf\n";
	print `cat /etc/inetd.conf`;
	print "\n\n";
	print "Properties of inetd service\n";
	print ">>> inetadm -p\n";
	print `inetadm -p`;
	print "\n\n";
	print ">>> rpcbind service running?\n";
	print ">>> svcs network/rpc/bind\n";
	print `svcs network/rpc/bind`;
	print "\n\n";
	print ">>> Verify the permissions on the rpcbind file\n";
	print ">>> ls -lL /usr/sbin/rpcbind\n";
	print `ls -lL /usr/sbin/rpcbind`;
	print "\n\n";
	print ">>> rshd installed?\n";
	print ">>> pkginfo SUNWrcmdr\n";
	print `pkginfo SUNWrcmdr`;
	print "\n\n";
	print ">>> rlogin running?\n";
	print ">>> svcs rlogin\n";
	print `svcs rlogin`;
	print "\n\n";
	print ">>> rexec running?\n";
	print ">>> svcs rexec\n";
	print `svcs rexec`;
	print "\n\n";
	print ">>> telnet running?\n";
	print ">>> svcs telnet\n";
	print `svcs telnet`;
	print "\n\n";
	print ">>> finger running?\n";
	print ">>> svcs finger\n";
	print `svcs finger`;
	print "\n\n";
	print ">>> FTP daemon invoked with -l option?\n";
	print ">>> inetadm -l ftp | grep in.ftpd\n";
	print `inetadm -l ftp | grep in.ftpd`;
	print "\n\n";
	print ">>> uucp running?\n";
	print ">>> svcs uucp\n";
	print `svcs uucp`;
	print "\n\n"; 
	print ">>> swat running?\n";
	print ">>> svcs swat\n";
	print `svcs swat`;
	print "\n\n"; 
	print ">>> TCP_WRAPPERS used?\n";
	print ">>> svcprop -p defaults inetd | grep tcp_wrappers\n";
	print `svcprop -p defaults inetd | grep tcp_wrappers`;
	print "\n\n";
	
	
	
}
elsif ($os =~ /aix/i)
{
	print "inetd/xinetd running?\n";
	print ">>> ps -ef | grep inetd\n";
	print `ps -ef | grep inetd`;
	print "\n\n";
	print "What services are enabled?\n";
	print ">>> grep -v \"^#\" /etc/inetd.conf\n";
	print `grep -v "^#" /etc/inetd.conf`;
	print "\n\n";
	print ">>> cat /etc/inetd.conf\n";
	print `cat /etc/inetd.conf`;
	print "\n\n";
	print ">>> ps -ef | grep inetd | grep \"-d\"\n";
	print `ps -ef | grep inetd | grep "-d"`;
	print "\n\n";
	print "portmap service running?\n";
	print ">>> ps -ef | grep portmap\n";
	print `ps -ef | grep portmap`;
	print "\n\n";
	print ">>> cat /etc/inittab\n";
	print `cat /etc/inittab`;
	print "\n\n";
	
}
print "\n";


print "#====================\n";
print "# V-835   | GEN004440\n";
print "# V-12006 | GEN004540\n";
print "# V-4690  | GEN004620\n";
print "# V-4384  | GEN004560\n";
print "# V-4692  | GEN004660\n";
print "# V-4693  | GEN004680\n";
print "# V-4694  | GEN004700\n";
print "# V-846   | GEN004820\n";
print "# V-4702  | GEN004840\n";
print "#====================\n";
if ($os =~ /linux/i || $os =~ /aix/i)
{
	print ">>> Sendmail config file:\n";
	print ">>> cat /etc/mail/sendmail.cf\n";
	print `cat /etc/mail/sendmail.cf`;
	print "\n\n";
	print ">>> Sendmail logging set to level 9?\n";
	print ">>> grep \"O L\" /etc/mail/sendmail.cf\n";
	print `grep "O L" /etc/mail/sendmail.cf`;
	print "\n\n";
	print ">>> or:\n";
	print ">>> grep LogLevel /etc/mail/sendmail.cf\n";
	print `grep LogLevel /etc/mail/sendmail.cf`;
	print "\n\n";
	print ">>> sendmail help disabled?\n";
	print ">>> grep HelpFile /etc/mail/sendmail.cf\n";
	print `grep HelpFile /etc/mail/sendmail.cf`;
	print "\n\n";
}
elsif ($os =~ /solaris/i)
{
	print ">>> sendmail enabled?\n";
	print ">>> svcs \*sendmail\*\n";
	print `svcs \\*sendmail\\*`;
	print "\n\n";
	print ">>> sendmail configuration\n";
	print ">>> svccfg -s svc:/network/smtp:sendmail listprop\n";
	print `svccfg -s svc:/network/smtp:sendmail listprop`;
	print "\n\n";
}

print ">>> Any test that requires a connection to the server to see if a\n";
print ">>> banner is displayed, anonymous ftp users are allowed,\n";
print ">>> or if you can enter debug mode, etc. can be accomplished\n";
print ">>> on your windows laptop by going to:\n";
print ">>>    +Start -> Run -> Cmd\n";
print ">>>    +At the command line type:\n";
print ">>>       ex. 1: telnet xxx.xxx.xxx.xxx [25]\n";
print ">>>       ex. 2: ftp xxx.xxx.xxx.xxx\n";
print ">>>            where xxx = the ip address and [#] is the port number.\n";
print ">>> You can simply take a screen shot as evidence.\n";
print "\n\n";

print "#==================\n";
print "# V-835 | GEN004440\n";
print "#==================\n";
print ">>> syslog config file:\n";
print ">>> cat /etc/syslog.conf\n";
print `cat /etc/syslog.conf`;
print "\n\n";

print "#===================\n";
print "# V-4689 | GEN004600\n";
print "#===================\n";
if ($os =~ /linux/i)
{
	print ">>> rpm -q sendmail\n";
	print `rpm -q sendmail`;
	print "\n\n";
	print ">>> rmp -q postfix\n";
	print `rpm -q postfix`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> /usr/lib/sendmail -d0 -bt < /dev/null\n";
	print `/usr/lib/sendmail -d0 -bt < /dev/null`;
	print "\n\n";

}
print "\n";

print "#====================\n";
print "# V-12004 | GEN003660\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> chkconfig --list gssftp\n";
	print `chkconfig --list gssftp`;
	print "\n\n";
	print ">>> chkconfig --list vsftpd\n";
	print `chkconfig --list vsftpd`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> svcs ftp\n";
	print `svcs ftp`;
	print "\n\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> Search for 'ftp' and 'telnet' in the inetd.conf file.\n";
	print ">>> See output for: V-29518 | GEN009340\n";
	print "\n\n";
}
print "\n";

print "#====================\n";
print "# V-840   | GEN004880\n";
print "# V-841   | GEN004900\n";
print "# V-4387  | GEN005000\n";
print "# V-12011 | GEN005040\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> ls -l /etc/ftpusers\n";
	print `ls -l /etc/ftpusers`;
	print "\n\n";
	print ">>> cat /etc/ftpusers\n";
	print `cat /etc/ftpusers`;
	print "\n\n";
	print ">>> ls -l /etc/vsftpd.ftpusers\n";
	print `ls -l /etc/vsftpd.ftpusers`;
	print "\n\n";
	print ">> cat /etc/vsftpd.ftpusers\n";
	print `cat /etc/vsftpd.ftpusers`;
	print "\n\n";
	print ">>> ls -l /etc/vsftpd/ftpusers\n";
	print `ls -l /etc/vsftpd/ftpusers`;
	print "\n\n";
	print ">>> cat /etc/vsftpd/ftpusers\n";
	print `cat /etc/vsftpd/ftpusers`;
	print "\n\n";
	print ">>> grep \"^ftp\" /etc/passwd\n";
	print `grep "^ftp" /etc/passwd`;
	print "\n\n";
	print ">>> ftp user's umask\n";
	print ">>> grep \"server_args\" /etc/xinetd.d/gssftp\n";
	print `grep "server_args" /etc/xinetd.d/gssftp`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> ls -l /etc/ftpd/ftpusers\n";
	print `ls -l /etc/ftpd/ftpusers`;
	print "\n\n";
	print ">>> cat /etc/ftpd/ftpusers\n";
	print `cat /etc/ftpd/ftpusers`;
	print "\n\n";
	print ">>> grep \"^ftp\" /etc/passwd\n";
	print `grep "^ftp" /etc/passwd`;
	print "\n\n";
	print ">>> umask settings\n";
	print ">>> cat /etc/ftpd/ftpaccess\n";
	print `cat /etc/ftpd/ftpaccess`;
	print "\n\n";
	
}
elsif ($os =~ /aix/i)
{
	print ">>> ls -l /etc/ftpusers\n";
	print `ls -l /etc/ftpusers`;
	print "\n\n";
	print ">>> cat /etc/ftpusers\n";
	print `cat /etc/ftpusers`;
	print ">>> grep \"^ftp\" /etc/passwd\n";
	print `grep "^ftp" /etc/passwd`;
	print "\n\n";
	print ">>> lsuser -a umask ftp\n";
	print `lsuser -a umask ftp`;
	print "\n\n";
}
print "\n";

print "#==================\n";
print "# V-850 | GEN005160\n";
print "#==================\n";
print ">>> X used?\n";
print ">>> egrep \"^x:5.*X11\" /etc/inittab\n";
print `egrep "^x:5.*X11" /etc/inittab`;
print "\n\n";
print ">>> Does a .Xauthority file exist in each user's home dir?\n";
print "\n";
for my $user (sort keys %pwd)
{
	my $home_dir = $pwd{$user}->{home_dir};
	print ">>> $user: ls -l $home_dir/.Xauthority\n";
	if ($home_dir eq "/")
	{
		print `ls -l /.Xauthority`;
	}
	else
	{
		print `ls -l $home_dir/.Xauthority`;
	}
	print "\n\n";
}
print "\n";

print "#====================\n";
print "# V-12017 | GEN005240\n";
print "#====================\n";
print ">>> xauth list\n";
print `xauth list`;

print "\n";

print "#====================\n";
print "# V-933   | GEN005300\n";
print "# V-22447 | GEN005305\n";
print "# V-22448 | GEN005306\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> Contents of snmpd.conf\n";
	for my $file (@snmpd_file)
	{
		print ">>> potential file: $file\n";
		print ">>> cat $file\n";
		print `cat "$file"`;
		print "\n\n";
	}
}
elsif ($os =~ /solaris/i)
{
	print ">>> Contents of snmpd.conf\n";
	for my $file (@snmpd_file)
	{
		print ">>> potential file: $file\n";
		print ">>> cat $file\n";
		print `cat "$file"`;
		print "\n\n";
	}
	print ">>> egrep '(v1|v2c|community|com2sec)' /etc/sma/snmp/snmpd.conf /var/sma_snap/snmpd.conf /etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf | grep -v '^#'\n"; 
	print `egrep '(v1|v2c|community|com2sec)' /etc/sma/snmp/snmpd.conf /var/sma_snap/snmpd.conf /etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf | grep -v '^#'`;
	print "\n\n";

}
elsif ($os =~ /aix/i)
{
	print ">>> Contents of snmpd.conf\n";	
	for my $file (@snmpd_file)
	{
		print ">>> potential file: $file\n";
		print ">>> cat $file\n";
		print `cat "$file"`;
		print "\n\n";
		print ">>> ls -l $file\n";
		print `ls -l "$file"`;
		print "\n\n";
	}
	print ">>> which snmpd\n";
	print `which snmpd`;
	print "\n\n";
}

print "#====================\n";
print "# V-22455 | GEN005450\n";
print "#====================\n";
for my $file (@syslog_file)
{
	print ">>> potential file: $file\n";
	print ">>> grep '@' $file | grep -v '^#'\n";
	print `grep '@' "$file" | grep -v '^#'`;
	print "\n\n";
}

print "#====================\n";
print "# V-4295  | GEN005500\n";
print "# V-22456 | GEN005501\n";
print "#====================\n";
for my $file (@sshd_file)
{
	print ">>> potential file: $file\n";
	print ">>> cat $file\n";
	print `cat "$file"`;
	print "\n\n";
}

print "#===================\n";
print "# V-4295  | GEN005540\n";
print "# V-4397  | GEN005560\n";
print "# V-12030 | GEN006620\n";
print "#===================\n";
print ">>> cat /etc/hosts.allow\n";
print `cat /etc/hosts.allow`;
print "\n\n";
print ">>> cat /etc/hosts.deny\n";
print `cat /etc/hosts.deny`;
print "\n\n";
print ">>> ls -la /etc/hosts.allow\n";
print `ls -la /etc/hosts.allow`;
print "\n\n";
print ">>> ls -la /etc/hosts.deny\n";
print `ls -la /etc/hosts.deny`;
print "\n\n";
print ">>> netstat -r | grep default\n";
print `netstat -r | grep default`;
print "\n\n";
print ">>> netstat -va\n";
print `netstat -va`;
print "\n\n";

print "#===================\n";
print "# V-1030 | GEN006220\n";
print "#===================\n";
for my $file (@smb_file)
{
	print ">>> potential file: $file\n";
	print ">>> cat $file\n";
	print `cat "$file"`;
	print "\n\n";
}


print "#====================\n";
print "# V-22550 | GEN007860\n";
print "# V-22551 | GEN007880\n";
print "# V-22552 | GEN007900\n";
print "# V-22553 | GEN007920\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> cat /proc/sys/net/ipv6/conf/all/accept_redirects (should be 0)\n";
	print `cat /proc/sys/net/ipv6/conf/all/accept_redirects`;
	print "\n\n";
	print ">>> egrep \"net.ipv6.conf.*forwarding\" /etc/sysctl.conf\n";
	print `egre "net.ipv6.conf.*forwarding" /etc/sysctl.conf`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> ndd /dev/ip6 ip6_ignore_redirect (should be 1)\n";
	print `ndd /dev/ip6 ip6_ignore_redirect`;
	print "\n\n";
	print ">>> ndd /dev/ip6 ip6_send_redirects (should be 0)\n";
	print `ndd /dev/ip6 ip6_send_redirects`;
	print "\n\n";
	print ">>> ndd /dev/ip6 ip6_forward_src_routed (should be 0)\n";
	print `ndd /dev/ip6 ip6_forward_src_routed`;
	print "\n\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> /usr/sbin/no -o ipignoreredirects (should be 1)\n";
	print `/usr/sbin/no -o ipignoreredirects`;
	print "\n\n";
	print ">>> /usr/sbin/no -o ipsendredirects (should be 0)\n";
	print `/usr/sbin/no -o ipsendredirects`;
	print "\n\n";
	print ">>> lsfilt -a\n";
	print `lsfilt -a`;
	print "\n\n";
	print ">>> /usr/sbin/no -o ip6srcrouteforward (should be 0)\n";
	print `/usr/sbin/no -o ip6srcrouteforward`;
	print "\n\n";
}
print "\n\n";

print "#====================\n";
print "# V-22578 | GEN008460\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> ls -l /proc/bus/usb\n";
	print `ls -l /proc/bus/usb`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> pkginfo SUNWusb\n";
	print `pkginfo SUNWusb`;
	print "\n\n";
}
elsif ($os =~ /aix/i)
{
	print ">>> lsdev -C | grep usb\n";
	print `lsdev -C | grep usb`;
	print "\n\n";
	print ">>> lslpp -l | usb\n";
	print `lslpp -l | grep usb`;
	
}
print "\n\n";

print "#====================\n";
print "# V-22588 | GEN008800\n";
print "#====================\n";
if ($os =~ /linux/i)
{
	print ">>> verify RPM signature validation is not disabled\n";
	print ">>> grep nosignature /etc/rpmrc /usr/lib/rpm/rpmrc /usr/lib/rpm/redhat/rpmrc ~root/.rpmrc\n";
	print `grep nosignature /etc/rpmrc /usr/lib/rpm/rpmrc /usr/lib/rpm/redhat/rpmrc ~root/.rpmrc`;
	print "\n\n";
	print ">>> verify YUM signature validation is not disabled\n";
	print ">>> grep gpgcheck /etc/yum.conf /etc/yum.repos.d/*\n";
	print `grep gpgcheck /etc/yum.conf /etc/yum.repos.d/*`;
	print "\n\n";
}
elsif ($os =~ /solaris/i )
{
	print ">>> verify package signature validation is not disabled\n";
	print ">>> grep \"authentication=quit\" /var/sadm/install/admin/default\n";
	print `grep "authentication=quit" /var/sadm/install/admin/default`;
	print "\n\n";
}
elsif ($os =~ /aix/i)
{
	#n/a
}
print "\n\n";



















print ">>> End Time\n";
print `date`;

#chomp;
#my($username, $password, $userid, $groupid, $userid_info, $home_dir, $shell) = split/:/;
#$pwd{$username}->{pwd} = $password;
#$pwd{$username}->{info} = $userid_info;
#$pwd{$username}->{userid} = $userid;
#$pwd{$username}->{home_dir} = $home_dir;
	
#$dupid{$userid}->{cnt}++;
#$grp{$groupid}->{$username}->{info} = $userid_info;

#clean up memory
#undef %pwd;
#undef %dupid;
#undef %grp;
#undef %groupmembers;
#undef %etc_grp;