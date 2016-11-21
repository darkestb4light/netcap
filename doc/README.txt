===========================================================================
Purpose:
	This is the general "README" for netcap. It basically discusses 
	how netcap came to be, overview, supported operating systems, the 
	various modes, and testing of netcap once you are ready to start 
 	monitoring.

Notes:
	- See "INSTALL.txt" for how to install netcap
	- See "README-FREEBSD.txt" for how to configure netcap to start 
	once at startup. This is for FreeBSD (and other *nix)
	- See "README-OSX.txt" for how to configure netcap to start 
	once at startup. This is for Apple's OS X (10.4 or later)
	- netcap is released under the GNU GENERAL PUBLIC LICENSE version 3
===========================================================================

	====================
	BACKGROUND OF NETCAP
	====================

I was asked to write a tool that could detect network traffic and alert 
based on unauthorized/unknown traffic. The challenge was to identify 
traffic where other security countermeasures (IDS, FW, etc.) were not
available or were inadequate for this use case. We wanted to watch the 
network and examine traffic at layer 3 and layer 4 (we were not concerned 
with payload at this point in time). This was ideal for security purposes 
as it could give visibility into traffic that was occurring across the 
network without us having to constantly watch the wire. For example, how 
would one know they were being port scanned or someone was attempting to 
connect to a listening port? They would need to be watching logs (assuming 
traffic was being logged) or watching the appropriate interface wire constantly.

The proof of concept had the following minimum requirements:
1. Be capable of gathering packets from the wire
2. Present them in a way where they could viewed and evaluated as acceptable
or unacceptable
3. Advise where unacceptable traffic happened

At first, I was not sure of how useful it would be due to other popular 
packet sniffers (tcpdump, wireshark). After all, these tools are fully 
capable of capturing traffic and could easily meet requirement #1 above. 
However, requirement #2 and requirement #3 would take more effort, beyond 
the default capabilities. One could use a default sniffer to capture the 
packets and write them to a file. Now, something would need to parse the 
binary data, interpret it so it could be analyzed, and then create something 
that could make conduct further monitoring and analysis against this dataset. 
These last two gaps caused me to reconsider proceeding with the idea. The 
approach also has to be able to inform of this type of activity in near real 
time. To do this with other tools would be complicated if not impossible 
without writing something anyway.

The strength netcap would have over other tools is its ability to create 
rules, based on host to host communication, and define what is either 
authorized or unauthorized. It would also be able to monitor traffic 
against these rules. It only made sense to have the same program capture 
and tie it all together. 

Being skeptical, I decided to write netcap in PERL. This way I could get 
it out quick as a proof of concept. 

It had proven to be useful as it provided real time notifications of host 
to host traffic across various networks. It allowed us to respond quickly 
to host traffic that was unauthorized or unknown on the network.

I may port it to C at some point in the future depending on the necessity.

===========================================================================

	==================
	OVERVIEW OF NETCAP
	==================

Netcap was written to be a network host to host discovery tool. Its 
purpose is the following:

1. Capture network packets in order to specify what is "normal" traffic
2. Learn from previously captured traffic and determine what is "normal" 
3. Monitor subsequent network traffic and alert when traffic is not 
"normal" (i.e., unauthorized or unknown).

It does NOT (currently) prevent traffic from occurring on the network. It 
is simply designed to alert when it sees traffic that is configured as 
unauthorized or unknown.

In an optimal setup, the client should be installed on servers where it can 
see network traffic. This would be similar to how one would setup an IDS. 
The main purpose is so it can passively sniff traffic and compare this 
against what is known to be authorized/unauthorized. The server can be 
placed anywhere as long as the client can communicate with it over the UDP 
socket.

===========================================================================

	=================
	SUPPORTED OS LIST
	=================

In theory any *nix system with an IP stack that supports libpcap. However, 
below are operating systems that have ran netcap successfully.

- OS X on both PPC and Intel processors
- FreeBSD
- CentOS
- RHEL

Note: 
Theoretically, it is possible to run netcap under Windows. You would need 
something like Cygwin, though. The main reason is to emulate the libpcap 
functionality as winpcap is the ported API for Windows. This was never 
pursued because the use case(s) at the time did not involve implementation 
on Windows platforms.

===========================================================================

	=======================
	VARIOUS MODES OF NETCAP
	=======================

This section documents the modes for netcap. For more information, see 
netcap --help.

Netcap has to know what traffic is authorized/unauthorized in order to 
monitor effectively and be useful. In order for netcap to know this 
information, it must "learn" what traffic is unacceptable and which can 
be ignored. Unless a "learn" file is created manually, this starts with 
capturing traffic from a network interface.

A. Capture Mode

This is normally the first mode used when you begin working with netcap. 
With no options, netcap will listen on the default interface for traffic. 
It writes packets in the form:

IPv4-src-addr:port > IPv4-dst-addr:port

Example:

192.168.0.20:56875 > 74.125.67.106:80
74.125.67.106:80 > 192.168.0.20:56875

Once netcap has captured the desired number of packets, it will write 
the data to its capture file (netcap.cap by default). The capture file 
is written to netcap's working directory by default (unless --capture-file 
is used). An interrupt (pressing 'control + c' or sending via a signal such 
as SIGINT or SIGTERM) or using --packet-count will cause netcap to stop 
capturing and exit.

You can also choose to specify a packet limit by passing it --packet-count 
and a maximum number of packets to capture. When this limit is reached, 
netcap will cleanly exit. One can grab a status of the netcap client as it 
is capturing packets by passing a "SIGUSR1" signal to the process. If this is 
done, netcap will dump stats similar to the following:

...
192.168.0.40:5353 > 224.0.0.251:5353
192.168.0.11:1053 > 239.255.255.250:8082
192.168.0.40:45164 > 239.255.255.250:1900
192.168.0.36:65484 > 172.20.25.18:443


-- User signal caught (pid: 45036).

Total packets:
Network: 44467	IP: 920
Requested: 100000	Captured: 920
Unique: 155

netcap (pid: 45036) continuing with capturing traffic.

192.168.0.40:49198 > 239.255.255.250:1900
192.168.0.36:65485 > 172.20.25.18:443
192.168.0.36:65486 > 143.192.7.24:443
192.168.0.36:62190 > 192.168.0.1:53
...

If there are more packets to capture from --packet-count or you omitted 
the option, netcap will go back to listening for packets.

If desired, you can choose to have netcap output more verbose packet detail. This is accomplished by specifying -pd or --packet-detail, when capturing. This 
will cause netcap to output more packet detail such as:

o The packet capture length actually captured
o Total packet length available
o The seconds value of the packet timestamp
o The microseconds value of the packet timestamp
o The transport protocol used for the packet
o The flags set in the packet transport protocol (if any)
o The bit sequence set in the packet transport protocol (if any)

Example:
...
192.168.0.45:64099 > 172.20.25.18:443|62:62:1478572176:577471|tcp:SYN:2
192.168.0.2:1048 > 239.255.255.250:8082|64:1514:1478572176:873878|udp:none:195
192.168.0.2:8291 > 239.255.255.250:29757|64:1162:1478572176:885485|tcp:none:48
192.168.0.11:1053 > 239.255.255.250:8082|64:505:1478572178:479122|udp:none:195
132.245.51.2:443 > 192.168.0.45:64094|64:1184:1478572180:733472|tcp:PSH/ACK:24
192.168.0.45:64094 > 132.245.51.2:443|64:66:1478572180:733607|tcp:ACK:16

When capturing packets, the amount of traffic (especially on a busy network) 
could be overwhelming. There are several options you can use to aid with 
minimizing this (in no particular order, especially since they can all be 
used together):

- The unique option (--unique) can be used to ensure only unique packet 
combinations, fitting the format of: IPv4-src-addr:port > IPv4-dst-addr:port, 
are returned.

Example WITHOUT using the unique functionality:
...
192.168.0.11:1053 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082

Total packets:
Network: 48	IP: 11
Requested: 10	Captured: 10
Unique: Not enabled
...

Example WITH using the unique functionality:
...
192.168.0.11:1053 > 239.255.255.250:8082
192.168.0.2:1048 > 239.255.255.250:8082

Total packets:
Network: 19	IP: 11
Requested: 10	Captured: 10
Unique: 2
...

In this case, the source hosts (192.168.0.11 and 192.168.0.2) were what 
made the traffic unique. Therefore, only these packets were returned. From a 
practical standpoint, this can cause a tremendous savings when later learning 
as only two packets would have been written to the capture file to be reviewed.

Suppose you only care about internal hosts to destinations over FTP and telnet 
ports. This is where you can leverage the regular expression feature of netcap: 
--regex. This feature is powerful but is currently limited to the packet 
format: IPv4-src-addr:port > IPv4-dst-addr:port. There are many ways one can 
approach this. See pcresyntax(3) for more detail.

Example:
...
192.168.0.11:23674 >  69.89.31.56:21
192.168.0.10:21364 >  176.74.176.187:23
...

The regular expression filter is good, but there may be some need to leverage 
another filter option that netcap offers. This feature leverage the filtering 
power from the PCAP library. Suppose you want to monitor activity to a website 
that concerns you. You could lookup the IP for the website and create a filter 
using the regular expression filter (--regex). This would be fine, but what if 
the IP changed or the list of CNAMEs were numerous? Rather than be concerned 
with that nonsense, we can simply leverage a simple filter and having this 
figured out. In this case, we rely on: --compile-filter and set it to the 
host we care about: "host (www.foo.com or www.bar.com)". See pcap-filter(7) 
for more detail on filtering syntax.

Example:
...
192.168.20.42:23674 > 204.236.134.199:80
204.236.134.199:80 > 192.168.20.42:23674
192.168.10.100:33621 > 104.27.138.186:443
104.27.138.186:443 > 192.168.10.100:33621
...

Another option that could be useful when capturing is to lookup up geographical 
information based on location and IPv4 information. This can be useful for 
trending where traffic is coming from or where it may be destined. For example, 
suppose you wanted to track what countries might be hitting your webserver or 
where egress traffic is going that is deemed unauthorized over services that 
may be unauthorized (telnet, tftp, etc). The geographical information is stored 
within a GEO database file obtained from Maxmind.com. The file is called 
"GeoLiteCity.dat". Currently, netcap relies on the "lite" version which is 
free. Also, netcap relies on the legacy version as opposed to using the GEO2 
version. This will likely be included in a later version. 

To use a GEO lookup, specify -gs/--geo-src-lookup or -gd/--geo-dst-lookup. The 
former will cause netcap to conduct a GEO lookup on the source traffic, while 
the latter will cause a GEO lookup on the destination traffic. They can be used 
separately or together as desired. There are two constants that can be passed 
to the option to tell netcap what lookup type you prefer. The constants are:
GEO_LOC_INFO and GEO_IP4_INFO. The former will cause netcap to lookup any 
location information, while the latter will cause a lookup of IPv4 information. 
The constants can be used separately or together as follows:

	...--geo-src-lookup fetch=GEO_LOC_INFO...
	...--geo-src-lookup fetch="GEO_LOC_INFO | GEO_IP4_INFO"...
	...--geo-dst-lookup fetch=GEO_IP4_INFO...
	...--geo-dst-lookup fetch="GEO_IP4_INFO | GEO_LOC_INFO"...

The database file is passed to the "db" argument. The parameter value must be a 
valid path, including the database file name, holding the GEO information. For 
example, if your database file resides in /netcap/etc/ and the file is called 
"GeoLiteCity.dat", you would point netcap to it as follows:

	--geo-dst-lookup ... db=/netcap/var/GeoLiteCity.dat
	
It is important to note that netcap will ignore a GEO lookup when GEO_LOC_INFO 
is used AND the IP address used for the lookup falls within the following:

	RFC 1918 "Private Use" IP addresses:
		10.0.0.0 - 10.255.255.255
		172.16.0.0 - 172.31.255.255
		192.168.0.0 - 192.168.255.255
	"Multicast" IP addresses:
		224.0.0.0 to 239.255.255.255
	"Broadcast" IP addresses:
		255.255.255.255
	"Autoconfiguration" IP Addresses:
		169.254.0.0 - 169.254.255.255
	"Loopback" IP addresses:
		127.0.0.0 - 127.255.255.255

If an IP falls within any of the above, the lookup value returned is prefixed 
with: PU, MC, BC, AC, LB respectively. Otherwise, a lookup is attempted 
and if a value is not found, NULL is returned for the respective value. 

The prefix identifiers map as follows:
	RFC1918 / "Private Use" = PU
	"Multicast" = MC
	"Broadcast" = BC
	"Autoconfiguration" = AC
	"Loopback" = LB

The fields for a location lookup (GEO_LOC_INFO) are:

		continent code
		country code (three character)
		country name
		city
		region name
		postal code
		latitude
		longitude
		time zone
		area code
		
The fields for a IPv4 lookup (GEO_IP4_INFO) are: 
	
	IPv4 range minimum
	IPv4 range maximum
	IPv4 mask
	IPv4 CIDR
	
As an example, we will capture 10 packets, fetch both source and destination 
information for location and IPv4. We named our GEO DB "geolite.dat" and 
point netcap to its location. We will only be concerned with port 80 or 443 
traffic (HTTP, HTTPS) where the traffic is for www.iana.org and the packets 
are from www.iana.org (i.e. return traffic). We will specify that we are only  
interested in unique packets. Finally, we will write the results to both stdout 
and to a capture file residing in our home: ~/Desktop/cap.txt:

$ ./netcap -c -s -cf ~/Desktop/cap.txt -gd fetch="GEO_IP4_INFO|GEO_LOC_INFO" db=~/Desktop/geolite.dat -gs fetch="GEO_IP4_INFO|GEO_LOC_INFO" db=~/Desktop/geolite.dat -pc 10 -re "^.*:(80\b|443)\s+>" -u --compile-filter "host www.iana.org"

...
192.0.32.8:443 > 192.168.0.45:63192|NA|USA|United States|Los Angeles|California|90066|34.0039|-118.4338|America/Los_Angeles|310|803|192.0.32.0|192.0.47.255|255.255.240.0|192.0.32.0/20|PU_continent_code|PU_country_code3|PU_country_name|PU_city|PU_region_name|RFC1918_postal_code|PU_latitude|PU_longitude|PU_time_zone|PU_area_code|PU_metro_code|192.168.0.0|192.168.255.255|255.255.0.0|192.168.0.0/16

Total packets:
Network: 203	IP: 14
Requested: 10	Captured: 10
Unique: 1
...

In the above example, we can see the destination (192.0.32.8) information is 
retrieved for both location and IPv4. The source (192.168.0.45) falls within 
the RFC1918 address space and is prefixed with "PU" (Private Use) identifier. 

The database file is usually updated every 30 days. It can be retrieved from:

http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz

Once, downloaded, it can be uncompressed and placed where your current GEO DB 
resides. In most cases, a default DB exists within netcap's default structure:

	/path/to/netcap/var/GeoLiteCity.dat
		OR
	/path/to/netcap/var/geolite.dat
	
IMPORTANT: It is encouraged that the existing DB is backed up as we have no 
control over how this DB file is updated. An update could, therefore, break 
functionality of this netcap feature. You have been warned.

Useful commands/options when capturing are:

-C, --Config
-cf, --capture-file
--compile-filter
-gd, --geo-dst-lookup 
-gs, --geo-src-lookup
-i, --interface
-li, --list-interfaces
-p --promiscuous
-pc, --packet-count
-pd, --packet-detail
-s, --stdout	
-S, --snaplen
-re, --regex
-rt, --read-timeout
-u, --unique

A sample of capturing with netcap might look like the following:

Example: Capture using the default interface indefinitely and place 
all packets to the default capture file "netcap.cap" (note: the below 
example would not display any packets to stdout as --stdout/-s would 
be needed):

netcap --capture

Example: Capture 100000 packets on interface en0, only store those that 
are unique to /tmp/capture.txt, and echo them to stdout as well so the 
user can see what's happening:

netcap --capture -pc 100000 -u -i en0 -cf /tmp/capture.txt -s

Example: Capture 500 packets on interface en0, only store those that 
are unique to /tmp/capture.txt, and echo them, along with the packet detail 
to stdout as well as ~/detail.cap.

netcap --capture -pc 500 -u -i en0 -cf /tmp/capture.txt -pd -s > ~/detail.cap

Example: Capture 1000 packets on the default interface, set the read timeout 
to 2 milliseconds, the capture length to 1500 bytes, ensure we are listening 
promiscuously, and ensure we only capture packets originating from an RFC1918 
address (internal network) to any destination where there is an attempt to 
connect over FTP, Telnet, or TFTP. Finally, write the data to /tmp/capture.txt 
and avoid writing to stdout.

netcap --capture -pc 1000 -cf /tmp/capture.txt -rt 2 -S 1500 --promiscuous \
--regex "((10.*)|(172.(1[6-9]|2[0-9]|3[01]).*)|(192.168.*)):.*>.*:2[013]|69\b"

Example: Capture 1500 packets promiscuously on the default interface, writing 
the unique packets to  ~/Desktop/cap.txt and to stdout. We will include the 
packet detail as we are only interested in connections that are being 
established or torn down. Finally, we are not concerned with optimization so 
we disable it (the default is to have it enabled).

netcap -c -cf ~/Desktop/cap.txt -p -s -pc 1500 -u -pd --compile-filter \
"tcp[tcpflags] & (tcp-syn) != 0 or tcp[tcpflags] & (tcp-ack) != 0 and \
tcp[tcpflags] & (tcp-push) == 0" optimize=false

Note: 
- Super user (root) privileges may be necessary in order to listen for 
traffic on an interface.
- While netcap does keep track of network packets, only layer 3 (IP) and 
layer 4 (TCP/UDP) packets are captured currently.
- You can't watch the packets as they enter the file (such as using 
"tail -f") because netcap keeps the data in memory until the packet limit 
is reached or an interrupt is sent. A interrupt can be sent to force the 
closure earlier at the user's convenience.
- All options can be combined (for example combining --unique, --regex, and 
--compile-filter can be pretty powerful based on needs)
- See netcap --help for more information for capture mode options.

B. Learn Mode

Once you feel enough traffic has been captured, using netcap's learning 
mode is the next logical option. This mode provides an interface between 
the captured traffic and the "rules" for what will become the learned 
traffic. If desired, netcap's learn file can be created/edited manually. 

With no other options, netcap will look for and read its default capture 
file (netcap.cap). It expects to find the file within its current working 
directory (unless --capture-file is used). 

Netcap will read each packet and present options that the user can interact 
with. There are several choices that can be made for a given packet:

o Learn as authorized traffic.
o Learn as unauthorized traffic.
o Save for later review (optional regex filter).
o Skip packet(s) (optional regex filter).
o Quit learning.

The first two are self explanatory and if chosen, the user will be given 
more choices:

o Modify traffic (using IP, CIDR, port wildcards).
o Modify traffic (using regular expressions).
o Leave traffic alone.
o Go back to previous menu.

From here, the user will decide whether to modify (and how) or to leave 
the traffic unmodified. If the user chooses to modify, they will be 
presented with what to do, based on the modification choice that was 
picked. Once the user is finished, netcap will write the rule to its 
default learn file (netcap.learn) and the traffic is said to be 
"learned".

Learned rules must fit the following format at this time:

[!];src[/mask]:prt > dst[/mask]:prt;[comment];[Day] Mon  dd hh:mm:ss YYYY;0|1

Record synopsis:
o Field 1 must be blank (authorized) or contain a "!" (unauthorized)
o Field 2 must be: source IP[/mask]:port > destination IP[/mask]:port
o Field 3 must be blank or can contain an optional user comment
o Field 4 must contain a date in the format listed above
o Field 5 must contain a zero (0) or a one (1) indicating if Field 2 
should be matched against captures using a regex

Note:
o Any line can be skipped by prefixing a hash (#) before the data
o Fields are delimited by a semicolon (;)
o If Field 2 is using a regex then Field 5 should be set (1)
o If the regex field (Field 5) is set:
	o Field 2 is minimally santitized
	o CIDR notations can only contain regular expressions as part of their 
	ports
	o Standard IP formats can contain full regular expressions. You can 
	simulate a CIDR block such as 192.168.0.0/24 as 192.168.0\.\d{1,3} or 	
	172.21.0.0/16 as 172.21\..*
	o The following alpha charachters are not allowed: a, c, e-z
o Records must be terminated by a newline

Useful commands/options when learning are:

--sort-learn
--test-re
-gr, --get-range
-gc, --get-cidr
-C, --Config
-cf, --capture-file
-lf, --learn-file
-nc, --no-comment
-nr, --no-reverse

Learning traffic in the hundreds or thousands (even with filtering options) 
can be daunting. It can be helpful to group the traffic first. For example: 
To filter destination ports (ascending order) and categorize then before 
learning, you can open a terminal and run the following against your capture 
file:

$ cat <path/to/capture-file> | perl -ne '/>\s.*:(.*?)$/ && print "$1\n"' | \
sort | uniq -c | sort -n

Then, you can determine what the majority of the traffic is and decide if 
it should be authorized/unauthorized or if it can be skipped/reviewed for 
later.

A fast way to remove ephemeral traffic is to enter learn mode and choose to 
review the traffic later (by saving it to a file). When presented with the 
option to create a filter, answer yes and enter the following filter:

.*\s>\s.*:\d{5}

The above will filter traffic where the destination is likely an ephemeral 
port (such as through a reply to the source in a conversation). In this way, 
you can filter this traffic out of the capture file and deal with the traffic 
separately or discard it altogether.

Netcap processes the learned rules like a firewall. This means as traffic 
is captured, it is compared against each rule, from top to bottom, until 
a match is found or until the end of the file. If no match is found, netcap 
treats the traffic as "unknown" and treats it in the same manner as it would 
for unauthorized traffic. This can create some false positives because as new 
traffic is introduced, you will need to learn this new traffic. If you ignore it 
and do not account for it through a rule (even setting it as authorized), netcap 
will continue notifications to the server (when in monitor mode). A solution 
would be to add the following rule to the end of the learned file you are using:

;0.0.0.0/0:* > 0.0.0.0/0:*;Remaining Traffic OK;Tue Aug 03 12:05:40 2010;0

The above rule translates as follows:
o Traffic hitting this rule is authorized
o CIDR blocks cover any IP address (0.0.0.0/0) and any port with a 
wildcard (*) for source and destination (i.e. match ALL traffic)
o A user comment documenting its purpose (optional)
o The date/time added
o No regular expression matching required for this rule

IMPORTANT: The above rule should be the LAST rule as it will match ALL 
traffic. Also, take care that since it will match ALL traffic, you 
could miss traffic that does not match any unauthorized traffic above 
it. It is not advised to add this rule as authorized until you are sure 
you're set for your environment. If you know what you wish to watch for, 
then it is less of a concern. For example, if you want to see if any 
services such as ftp, tftp, telnet, etc., are being used, you can watch 
for these services and then feel confident adding the rule. Alternatively, 
just set the rule to unauthorized and you should quickly see if anything is 
awry. For example:

# watch for FTP, TELNET, and TFTP
!;0.0.0.0/0:* > 0.0.0.0/0:(2[013]|69)\b;...;1
;0.0.0.0/0:* > 0.0.0.0/0:*;...;0

# catch anything NOT already learned
... [other rules here] ...
!;0.0.0.0/0:* > 0.0.0.0/0:*;...;0

Note:
- netcap will ignore captured traffic that matches a learned rule. The 
user will have an option to see the rule it matches (to ensure it is 
what they intended) or skip to the first packet that is unlearned.
- You MUST capture in order to use netcap's learn mode but you do not 
have to have a learn file to monitor. You will be warned when starting 
a netcap client, however. This warning is presented to advise you that the 
netcap client will treat all unlearned traffic as "unknown" and will advise 
the netcap server. This could flood your server (and you) with notifications. 
Proceed at your own risk.
- For more detailed information on netcap's learn file structure, see the 
"sample.learn" file that should have come with this bundled release.
- Using netcap's --test-re command can aid with ensuring your traffic 
patterns match your rules by testing expressions against the traffic pattern. 
There is loose validation and --test-re should NOT be relied on to be 100% 
accurate (you should learn rules by using --learn to be sure). Here are some 
examples:
	
	** If you want to ensure a value matches exactly, use a word boundary 
	such as: <value-to-match>\b or \b<value-to-match>\b
	** The more complicated the expression, the more likely you will not 
	end up with what you intend or the more hinderance it will have on 
	netcap's performance (rule of thumb: KIS (Keep It Simple))

	- Octet (no more than three per octet, ranging from 0-255):
		- match 10-16, 17-21, 240-244, 246-254:
		((1(0|[1-9])|2[01])|24[0-4]|24[6-9]|25[0-5])
		- match all numbers in one numbered position: 
		\d, [0-9]
		- match all numbers in two numbered position: 
		\d\d, \d{2}, [0-9][0-9], [0-9]{2}
		- match all numbers: 
		\d\d\d, \d{1,3}, [0-9]{1,3}, *
	- Port Match (no more than 5 positions, ranging from 0-65535):
		- match FTP, Telnet, TFTP:
		(2[013]|69)
		- match well known ports (0-1023):
		([1-9]?[0-9]{1,2})|(10[01][0-9]|102[03])
		- match all ports:
		\d{1,5}, *
		
- See ./netcap --help for more information on learn mode options.

C. Monitor Mode

Once the desired traffic has been learned, the final mode is to monitor. 
This involves starting at least two instances of netcap. The first being 
a netcap server. The second being a netcap client. 

	=============
	NETCAP SERVER
	=============

The server creates a UDP socket on a specified port given by the user. 
With no other options, it simply awaits a netcap client to notify of 
unauthorized traffic. If logging is enabled (see: --log option), the 
client messages will show here. 

Upon receiving such traffic, it begins building a cache within memory. 
This cache is maintained until it is signaled to dump to its configured 
cache file (by default, this is netcap.cache). The signal can be a 
SIGUSR1 sent to the server process or could be set on an interval (see:
--packet-count option). If notifications are enabled, the server will 
also build a notification message (see: --notify option). This is useful 
for automating the alert process. In lieu of the notification option, 
one can refer to the server log to see incoming client messages.

The server supports SIGTERM, SIGINT, and SIGUSR1 signals. You can send 
the server a SIGTERM or SIGINT signal to stop the server process. If the 
server is running in the foreground (i.e. you haven't passed it --daemon), 
you can choose to press "control + c" to stop the netcap server. 

	=============
	NETCAP CLIENT
	=============

The client will begin listening for traffic on the default interface 
(unless --interface option is used). By default, it listens for all 
traffic destined for the interface to which is bound. Upon receipt of a 
network packet, it strips the source IP/port and destination IP/port 
and discards the payload. 

It then compares the captured traffic against the "learned" rules that 
should have been created prior. If a match is located, the client stops 
further checking. Otherwise, it assumes the traffic is "unknown". Netcap 
treats its learn file similar to a firewall. It is important that the 
most restrictive rules go before the least restrictive rules.

For example, let's say you want to know about traffic to some website, 
but all other HTTP traffic is okay and can be ignored. If you set up the 
rules in the undesired order, the traffic would match the rule that 
says HTTP traffic is okay and the client would ignore it, such as with 
the following:

…
;0.0.0.0/0:* > 0.0.0.0/0:(80|443)\b;HTTP Okay;[Rest of rule omitted]
;0.0.0.0/0:(80|443)\b > 0.0.0.0/0:*;HTTP Okay;[Rest of rule omitted]
!;0.0.0.0/0:* > 98.76.543.210:(80|443)\b;To Site;[Rest of rule omitted]
!;98.76.543.210:(80|443)\b > 0.0.0.0/0:*;From Site;[Rest of rule omitted]
…

The above will cause ALL traffic to match 0.0.0.0/0. This is fine if your 
only concerned with the port, which we are in this example. So, we define 
common HTTP and HTTPS ports. We could still be fine if it weren't that the 
rule is configured as authorized. In this case, all traffic to/from ports 
80 or 443 will match and be ignored. Below is most likely what you'd want:

…[Possibly other rules here]…
!;0.0.0.0/0:* > 98.76.543.210:(80|443)\b;To Site;[Rest of rule omitted]
!;98.76.543.210:(80|443)\b > 0.0.0.0/0:*;From Site;[Rest of rule omitted]
;0.0.0.0/0:* > 0.0.0.0/0:(80|443)\b;HTTP Okay;[Rest of rule omitted]
;0.0.0.0/0:(80|443)\b > 0.0.0.0/0:*;HTTP Okay;[Rest of rule omitted]
…[Possibly other rules here]…

Or better yet, if there is something specific that you want and you do 
not care about the rest of the protocols, you could drastically reduce 
your rules. So using the above example:

…[Possibly other rules here]…
!;0.0.0.0/0:* > 98.76.543.210:(80|443)\b;To Site;[Rest of rule omitted]
;0.0.0.0/0:* > 0.0.0.0/0:*;All other traffic okay;[Rest of rule omitted]

Note:
Use the above rule (0.0.0.0/0:* > 0.0.0.0/0:*) once you are sure there is 
no other traffic to know about. If there is, those rules must be placed 
before this rule, since this rule matches ALL possible traffic.

The client notifies the netcap server by sending it the packet information 
(and some other stuff) via the UDP socket created by the server. 

If logging is enabled for the client, this information can be found here. 
Finally, it goes back to listening for traffic. If --packet-count is used, 
the client will stop once the desired packets have been captured.

The client supports signals just like the server. You can send the client a 
SIGTERM or SIGINT signal to stop the client process. If the client is running 
in the foreground (i.e. you haven't passed it --daemon), you can choose to 
press "control + c" to stop the netcap client. You can also choose to 
specify a packet limit by passing it --packet-count and a maximum number 
of packets to capture. When this limit is reached, netcap will cleanly exit. 

When a SIGUSR1 is sent, netcap will look to process its learn file. This can 
be useful if rules were changed or added.

If more granularity is needed, you can leverage powerful features such as the 
--regex and --compile-filter options. These can be leveraged separately or 
together as needed.

As mentioned in the ClIENT section of this document, another option that could 
prove useful is netcap's ability to conduct geographical and IPv4 lookups. This 
can be beneficial for analysis and analytics. See the CLIENT section to see 
more information. In this section, we assume to are aware of why you would want 
to use it and just want to illustrate a simple example scenario:

Scenario:
=========

You decide that traffic to www.blackhat.com is unauthorized - you worry that no 
good can possible come from visiting this site - in all seriousness, the point 
is that www.blackhat.com can be replaced with any website that is ACTUALLY a 
site that could cause harm; just using this site as an example only :)

We are in a monitoring situation and have a client and server. In this example, 
we are interested in monitoring traffic to www.blackhat.com where data is being 
passed (not concerned with other traffic). We will conduct a source and server 
GEO DB lookup for both location and IPv4. There are other options being used, 
but the only other real important one is to note that we only want unique 
traffic returned. On the server side, we have typical options specified. One 
interesting option is -pc (--packet-count) is set to 1. In this example, we 
want to know when see even 1 event. Since we have also asked our server to 
notify us, we would immediately learn of this happening, should we not be 
watching the logs (or the console as we were not running in daemon mode).

Client:
=======

$ ./netcap -m --client localhost 55555 --log=client ~/Desktop/client.log -s -p -pd --compile-filter "host www.blackhat.com && (tcp[tcpflags] & (tcp-push) != 0)" -gd fetch="GEO_IP4_INFO|GEO_LOC_INFO" db=etc/geolite.dat -gs fetch="GEO_LOC_INFO|GEO_IP4_INFO" db=etc/geolite.dat -u 

Server:
=======

$ ./netcap -m --server localhost 55555 --cache-file ~/Desktop/cache.txt --cache-key-dst --log=server ~/Desktop/server.log -n out=~/Desktop/notify.txt --sort-cache-date -pc 1 -s

Now that we have our monitoring up, we sit back and relax. At some point, we 
see events. This happens after traffic to www.blackhat.com is seen. Below are 
the example results. Take note of the amount traffic observed on the client 
compared to that of the client (thanks to the unique flag):

Client:
=======

Client Running|Sun Nov 20 16:32:36 2016|netcap|42658|localhost:55555|udp
Binding to interface: en0... Listening (promiscuous mode = Yes)...
Server Message|Sun Nov 20 16:32:39 2016|netcap|42658|localhost:55555|udp|192.168.0.45:63980 > 104.20.65.243:80|0|64:652:1479684759:35314|tcp:PSH/ACK:24|PU_continent_code|PU_country_code3|PU_country_name|PU_city|PU_region_name|PU_postal_code|PU_latitude|PU_longitude|PU_time_zone|PU_area_code|PU_metro_code|192.168.0.0|192.168.255.255|255.255.0.0|192.168.0.0/16|NA|USA|United States|San Francisco|California|94107|37.7697|-122.3933|America/Los_Angeles|415|807|104.16.0.0|104.31.255.255|255.240.0.0|104.16.0.0/12
Server Message|Sun Nov 20 16:32:39 2016|netcap|42658|localhost:55555|udp|192.168.0.45:63961 > 104.20.65.243:443|0|64:875:1479684759:234384|tcp:PSH/ACK:24|PU_continent_code|PU_country_code3|PU_country_name|PU_city|PU_region_name|PU_postal_code|PU_latitude|PU_longitude|PU_time_zone|PU_area_code|PU_metro_code|192.168.0.0|192.168.255.255|255.255.0.0|192.168.0.0/16|NA|USA|United States|San Francisco|California|94107|37.7697|-122.3933|America/Los_Angeles|415|807|104.16.0.0|104.31.255.255|255.240.0.0|104.16.0.0/12
Server Message|Sun Nov 20 16:32:39 2016|netcap|42658|localhost:55555|udp|192.168.0.45:63985 > 104.20.65.243:80|0|64:732:1479684759:580722|tcp:PSH/ACK:24|PU_continent_code|PU_country_code3|PU_country_name|PU_city|PU_region_name|PU_postal_code|PU_latitude|PU_longitude|PU_time_zone|PU_area_code|PU_metro_code|192.168.0.0|192.168.255.255|255.255.0.0|192.168.0.0/16|NA|USA|United States|San Francisco|California|94107|37.7697|-122.3933|America/Los_Angeles|415|807|104.16.0.0|104.31.255.255|255.240.0.0|104.16.0.0/12
Server Message|Sun Nov 20 16:32:39 2016|netcap|42658|localhost:55555|udp|104.20.65.243:443 > 192.168.0.45:63961|0|64:571:1479684759:609745|tcp:PSH/ACK:24|NA|USA|United States|San Francisco|California|94107|37.7697|-122.3933|America/Los_Angeles|415|807|104.16.0.0|104.31.255.255|255.240.0.0|104.16.0.0/12|PU_continent_code|PU_country_code3|PU_country_name|PU_city|PU_region_name|PU_postal_code|PU_latitude|PU_longitude|PU_time_zone|PU_area_code|PU_metro_code|192.168.0.0|192.168.255.255|255.255.0.0|192.168.0.0/16
... [OTHER UNIQUE TRAFFIC OMITTED] ...

... [AT SOME POINT AN INTERRUPT IS SENT] ...

-- Interrupt signal caught. Wrapping up...

Total packets:
Network: 3373	IP: 3194
Requested: Indefinite amount	Captured: 3194
Unique: 15
...

Server:
=======

Server Running|Sun Nov 20 16:32:33 2016|netcap|42657|localhost:55555|udp
Client Message|Sun Nov 20 16:32:39 2016|netcap|42657|localhost:55555 < 127.0.0.1:64851|udp|192.168.0.45 > 104.20.65.243:80|0|64:652:1479684759:35314|tcp:PSH/ACK:24|PU_continent_code|PU_country_code3|PU_country_name|PU_city|PU_region_name|PU_postal_code|PU_latitude|PU_longitude|PU_time_zone|PU_area_code|PU_metro_code|192.168.0.0|192.168.255.255|255.255.0.0|192.168.0.0/16|NA|USA|United States|San Francisco|California|94107|37.7697|-122.3933|America/Los_Angeles|415|807|104.16.0.0|104.31.255.255|255.240.0.0|104.16.0.0/12
Client Message|Sun Nov 20 16:32:39 2016|netcap|42657|localhost:55555 < 127.0.0.1:64851|udp|192.168.0.45 > 104.20.65.243:443|0|64:875:1479684759:234384|tcp:PSH/ACK:24|PU_continent_code|PU_country_code3|PU_country_name|PU_city|PU_region_name|PU_postal_code|PU_latitude|PU_longitude|PU_time_zone|PU_area_code|PU_metro_code|192.168.0.0|192.168.255.255|255.255.0.0|192.168.0.0/16|NA|USA|United States|San Francisco|California|94107|37.7697|-122.3933|America/Los_Angeles|415|807|104.16.0.0|104.31.255.255|255.240.0.0|104.16.0.0/12

In the above, we can see TWO unique events for the server. One for port 80 and 
one for port 443. Also, note the GEO DB data returned (see CLIENT section for 
what the "PU" prefix means for the IP of 192.168.0.45 in the event).

Useful commands/options when monitoring are:
	
	Shared For Client and Server:

-m, --monitor
-C, --Config
-s, --stdout
-pc, --packet-count
--log
-d, --daemon
	
	Specific To Client:

--compile-filter
-gd, --geo-dst-lookup 
-gs, --geo-src-lookup	
-i, --interface
-S, --snaplen
-rt, --read-timeout
-p, --promiscuous
-pd, --packet-detail
-u, --unique
-lf, --learn-file
-re, --regex

	Specific To Server:

-n, --notify 
--cache-file
--sort-cache-date
--cache-key-dst

Note:
- You MUST capture in order to use netcap's learn mode but you do not 
have to have a learn file to monitor. You will be warned when starting 
a netcap client. Proceed at your own risk.
- See ./netcap --help for more information for monitor mode options.

===========================================================================

	==============
	TESTING NETCAP
	==============

Note: Before going any further, it is assumed netcap is installed. See 
INSTALL.txt if necessary.

1. Test install of netcap

./netcap --help

Expected output: 
	- The netcap help menu is outputted to stderr
Unexpected output: 
	- See INSTALL.txt

2. Test capture mode (elevated privileges may be required)
** Split on multiple lines for readability 

./netcap --interface <device> --capture --packet-count 10 --unique --stdout \
--capture-file </path/to/capture-file>

Expected output: 
	- Captured packets outputted to stdout as well as configured capture 
	location
Unexpected output: 
	- Make sure you are root before capturing traffic
	- Make sure a valid device is defined for the netcap --interface 
	option. If in doubt of the available interfaces that can be 
	captured from, run: sudo ./netcap --list-interfaces
	- Ensure there is traffic on the interface to capture (you 
	can use a tool like "tcpdump", "nmap", or "nc" to test)

3. Test learn mode 
** Split on multiple lines for readability 

./netcap --learn --capture-file </path/to/capture-file> --learn-file \
</path/to/learn-file>

Expected output: 
	- Traffic should be read from the configured locations for 
	captured traffic and learned data should be written to the 
	configured location for learned traffic
Unexpected output: 
	- Did you capture traffic first? If not, this must be done so 
	netcap knows what traffic to learn (see step 2)
	- Is the capture file empty?
	- Is the traffic not formatted as follows:
		IPv4-src_addr:src-port > IPv4-dst_addr:dst-port
		Example: 192.168.0.50:32658 > 72.15.208.34:80
	- Make sure the paths to capture and learn traffic are valid.  

4. Test necap with the "sample" learn file

Note: If you wish to test your own learn file against netcap, proceed to step 
#5 and point your netcap client to the learn file you created in step #3. 
Otherwise, continue with step #4 below:

Edit netcap's "sample.learn" file and modify appropriate section as 
indicated within the file. You will need the following information 
beforehand:
	- IP addresses of hosts you wish to be unauthorized sources. These 
	addresses will be used to replace the "IPv4-src_addr" notation
	- IP addresses of hosts you wish to be unauthorized destinations. 
	These addresses will be used to replace the "IPv4-dst_addr" 
	notation 
	- Ports that should not be accessed (if the sample ports are not 
	desired)

Note: 
- A good source for the test could be the server where the netcap client(s) 
are running - This keeps traffic scoped for the test
- A good destination for the test could be the server where the netcap 
server is running - This keeps traffic scoped for the test
- netcap "sample.learn" file should only be used for testing and not 
modified for "production" use. This is because it should be kept as a reference 
as it contains other documentation.

5. Test monitor mode: 

5a. Start server (NON daemon)
** Split on multiple lines for readability 

./netcap --monitor --server <host> <port> --notify out=<path/to/notify-file> \
--cache-file </path/to/cache-file> --cache-key-dst --log=server \
</path/to/server-log-file> --stdout --packet-count 10

Expected output: 
	- netcap should start listening on <host> and <port> and display 
	information to stdout
	- Log files should be created in their configured locations as provided 
	above
	- The server should dump the cache and create a notification file (as 
	specified above) after 10 unique packets
Unexpected output:
	- Make sure host and port are correct
	- You will not receive alerts until you proceed with 5b 

5b. Start client (NON daemon)
** Split on multiple lines for readability 

./netcap --monitor --client <host> <port> --interface <device> --promiscuous \
--learn-file </path/to/learn-file> --log=client out=<path/to/client-log-file> \
--packet-count 1000 --unique --stdout

Expected output: 
	- netcap should start listening on <host> and <port> and display 
	information to stdout
	- Log files should be created in their configured locations as 
	provided above
	- The client should cleanly exit after 1000 unique packets
Unexpected output:
	- Make sure you are root before monitoring as a client
	- Make sure <host> and <port> are valid
	- Make sure a valid device is defined for the netcap --interface 
	option. If in doubt of the available interfaces that can be 
	captured from, run: sudo ./netcap --list-interfaces
	- Make sure you have a netcap server running
	- If you specified --packet-count and the client stopped because the 
	number of packets were reached, increase the packet limit or omit the 
	option altogether (when ready to stop, send a TERM/INT signal to the 
	process or press control + c)

6. Test monitoring in daemon mode. The easiest way to test this is to use 
the below commands:

Server:
** Split on multiple lines for readability 

./netcap --monitor --server <host> <port> --notify out=<path/to/notify-file> \
--cache-file </path/to/cache-file> --cache-key-dst --log=server \
</path/to/server-log-file> --packet-count <count> --daemon

** NOTE: If you are not sure what count to use, keep what you tested with in 
step 5a or omit the option. You can always send a SIGUSR1 to dump the cache 
and build a notification
** NOTE: The process id can be found in the server log or you could look at 
the running processes to find it
** NOTE: You can tail the server log to keep status on the various ongoings

Client:
** Split on multiple lines for readability 

./netcap --monitor --client <host> <port> --interface <device> --promiscuous \
--learn-file </path/to/learn-file> --log=client out=<path/to/client-log-file> \
--packet-count 1000 --unique --daemon

** NOTE: If you are not sure what count to use, keep what you tested with in 
step 5b or omit the option. You can always send a SIGUSR1 to refresh the 
client, should you update the netcap learn file
** NOTE: The process id can be found in the client log or you could look at 
the running processes to find it
** NOTE: You can tail the client log to keep status on the various ongoings


7. Test client/server communication

Once server and client are running, generate some traffic. 

Use the learn file you created or the rules you modified in the default 
"sample.learn" file. Generate traffic to the destinations/ports you defined 
as unauthorized. Example:

You could port scan the server host 

sudo nmap -A -T4 -p<unauth-port,…> <IPv4-dst_addr>

Or, telnet to some unauthorized ports

telnet <IPv4-dst_addr> <unauth-port>

Expected output: 
	- Should see data in client / server logs
	- Should see the server dump its cache and generate a notification
	- Should see the client stop (after <count> packets, if you specified the 
	option)
Unexpected output:
	- Make sure host and port are correct
	- You will not receive alerts until your client is running or until you 
	generate unauthorized (or unknown) traffic
	- Make sure you are root before monitoring as a client
	- Make sure <host> and <port> are valid
	- Make sure a valid device is defined for the netcap --interface 
	option. If in doubt of the available interfaces that can be 
	captured from, run: sudo ./netcap --list-interfaces
	- Make sure you have a netcap server running

8. Test refresh client/server script (elevated privileges may be required)

8a. **CLIENT SIDE ONLY

- Edit nc-refresh-client
- Modify based on your needs (script should have notes to follow)
- Execute script

--> should send signal USR1 to process; check client log or stderr if you 
did not use daemon mode (note: in daemon mode, errors will be sent to 
netcap.error.log by default)

8b. **SERVER SIDE ONLY

- Edit nc-refresh-server
- Modify based on your needs (script should have notes to follow)
- Execute script

--> should send signal USR1 to process; check server log or stderr if you 
did not use daemon mode (note: in daemon mode, errors will be sent to 
netcap.error.log by default)
--> should have created a cache file in configured location
--> should have created a notification file in configured location

9. Test shutdown client/server script  (elevated privileges may be needed)

9a. **CLIENT SIDE ONLY

Execute nc-stop-client 

-> client should be stopped; verify process is no longer running

9b. **SERVER SIDE ONLY

Execute nc-stop-server

-> server should be stopped; verify process is no longer running

10. Test starting client/server script  

(elevated privileges may be required)

10a. **CLIENT SIDE ONLY

- Edit nc-start-client
- Modify based on your needs (script should have notes to follow)
- Execute script

--> should start the client based on your modifications; check to see the 
client is running (you should see a log created if you specified --log)

10b. **SERVER SIDE ONLY

- Edit nc-start-server
- Modify based on your needs (script should have notes to follow)
- Execute script

--> should start the server based on your modifications; check to see the 
server is running (you should see a log created if you specified --log)

====

If the above all worked out, feel free to stop the client/server and clean 
up the logs, capture files, learn files, cache files, and notification files.

Check out the following scripts to see if you wish to use them:

--> nc-archive
	Archives the server cache and notification files
--> nc-refresh-client
	Reloads netcap's learn file; useful if changes are made to it (only useful 
	when monitoring)
--> nc-refresh-server
	Dumps netcap's memory cache to disk and notifies (if configured to do so); 
	(only useful when monitoring) 
--> nc-start-client
	Attempts to start a netcap client	
--> nc-start-client-onload
	Allows a netcap client to be started upon boot (note: If running on OSX, 
	see: netcap-client.plist included in this release instead)
--> nc-start-server
	Attempts to start a netcap server
--> nc-start-server-onload
	Allows a netcap server to be started upon boot (note: If running on OSX, 
	see: netcap-server.plist included in this release instead)
--> netcap-client.plist
	Allows a netcap client to be started upon boot (use if running on OSX 
	instead of nc-start-client-onload)
--> netcap-server.plist
	Allows a netcap server to be started upon boot (use if running on OSX 
	instead of nc-start-server-onload)
--> nc-stop-client
	Attempts to stop a netcap client
--> nc-stop-server
	Attempts to stop a netcap server
	
