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
connect to a listening port? They would need to be watching logs (assuming traffic was being logged) or watching the appropriate interface wire 
constantly.

The proof of concept had the following minimum requirements:
1. Be capable of gathering packets from the wire
2. Present them in a way where they could viewed and evaluated as acceptable
or unacceptable
3. Advise where unacceptable traffic happened

At first, I was not sure of how useful it would be due to other popular 
packet sniffers (tcpdump, wireshark). After all, these tools are fully 
capable of capturing traffic and could easily meet requirement #1 above. However, requirement #2 and requirement #3 would take more effort, beyond 
the default capabilities. One could use a default sniffer to capture the 
packets and write them to a file. Now, something would need to parse the 
binary data, interpret it so it could be analyzed, and then create something 
that could make conduct further monitoring and analysis against this dataset. These last two gaps caused me to reconsider proceeding with the idea. The  
approach also has to be able to inform of this type of activity in near real time. To do this with other tools would be complicated if not impossible 
without writing something anyway.

The strength netcap would have over other tools is its ability to create 
rules, based on host to host communication, and define what is either 
authorized or unauthorized. It would also be able to monitor traffic against 
these rules. It only made sense to have the same program capture and tie it 
all together. 

Being skeptical, I decided to write netcap in PERL. This way I could get 
it out quick as a proof of concept. 

It has proven to be useful as it provides real time notifications of host to host traffic across our local network. It allows us to respond quickly to host traffic that is unauthorized or unknown on the network. 

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
is simply designed to alert when it sees traffic that is configured as unauthorized or unknown.

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
./netcap --help.

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
as SIGINT or SIGTERM) or using --packet-count will cause netcap to stop capturing and exit.

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

If there are more packets to capture from --packet-count or you omitted the 
option, netcap will go back to listening for packets.

Useful commands/options when capturing are:

-li, --list-interfaces
-C, --Config
-s, --stdout	
-i, --interface
-S, --snaplen
-rt, --read-timeout
-p --promiscuous
-pc, --packet-count
-u, --unique
-cf, --capture-file
-re, --regex

A sample of capturing with netcap might look like the following:

Example: Capture using the default interface indefinitely and place all 
packets to the default capture file: netcap.cap

netcap --capture

Example: Capture 100000 packets on interface en0, only store those that 
are unique to /tmp/capture.txt, and echo them to stdout as well so the user 
can see what's happening

netcap --capture -pc 100000 -u -i en0 -cf /tmp/capture.txt -s

Note: 
- Super user (root) privileges may be necessary in order to listen for 
traffic on an interface.
- While netcap does keep track of network packets, only layer 3 (IP) and 
layer 4 (TCP/UDP) packets are captured currently.
- You can't watch the packets as they enter the file (such as using 
"tail -f") because netcap keeps the file descriptor open while it is writing 
the data. A interrupt can be sent to force the closure earlier at the user's convenience.
- See netcap --help for more information for capture mode options.

B. Learn Mode

Once you feel enough traffic has been captured, using netcap's learning 
mode is the next logical option. This mode provides an interface between 
the captured traffic and the "rules" for what will become the learned 
traffic. If desired, netcap's learn file can be created/edited manually. 

With no other options, netcap will look for and read its default capture 
file (netcap.cap). It expects to find the file within its current working 
directory (unless --capture-file is used). 

netcap will read each packet and present options that the user can interact 
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
learning, you can open a terminal and run the following against your capture file:

$ cat <path/to/capture-file> | perl -ne '/>\s.*:(.*?)$/ && print "$1\n"' | \
sort | uniq -c | sort -n

Then, you can determine what the majority of the traffic is and decide if 
it should be authorized/unauthorized or if it can be skipped/reviewed for 
later.

A fast way to remove ephemeral traffic is to enter learn mode and choose to review the traffic later (by saving it to a file). When presented with the option to create a filter, answer yes and enter the following filter:

.*\s>\s.*:\d{5}

The above will filter traffic where the destination is likely an ephemeral 
port (such as through a reply to the source in a conversation). In this way, 
you can filter this traffic out of the capture file and deal with the traffic separately or discard it altogether.

netcap processes the learned rules like a firewall. This means as traffic 
is captured, it is compared against each rule, from top to bottom, until 
a match is found or until the end of the file. If no match is found, netcap 
treats the traffic as "unknown" and treats it in the same manner as it 
would for unauthorized traffic. This can create some false positives 
because as new traffic is introduced, you will need to learn this new 
traffic. If you ignore it and do not account for it through a rule (even setting it as authorized), netcap will continue notifications to the server (when in monitor mode). A solution would be to add the following rule to the end 
of the learned file you are using:

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
your set for your environment. If you know what you wish to watch for, 
then it is less of a concern. For example, if you want to see if any 
services such as ftp, tftp, telnet, etc., are being used, you can watch for these services and then feel confident adding the rule. Alternatively, just 
set the rule to unauthorized and you should quickly see if anything is awry. 
For example:

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
a netcap client, however. This warning is presented to advise you that the netcap client will treat all unlearned traffic as "unknown" and will advise 
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

The server supports SIGTERNM, SIGINT, and SIGUSR1 signals. You can send the server a SIGTERM or SIGINT signal to stop the server process. If the server  
is running in the foreground (i.e. you haven't passed it --daemon), you can choose to press "control + c" to stop the netcap server. 

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

Useful commands/options when monitoring are:
	
	Shared For Client and Server:

-m, --monitor
-C, --Config
-s, --stdout
-pc, --packet-count
--log
-d, --daemon
	
	Specific To Client:
	
-i, --interface
-S, --snaplen
-rt, --read-timeout
-p, --promiscuous
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
	The netcap help menu is outputted to stderr
Unexpected output: 
	See INSTALL.txt

2. Test capture mode (elevated privileges may be required)

./netcap --interface <device> --capture --packet-count 10 --unique --stdout --capture-file </path/to/capture-file>

Expected output: 
	Captured packets outputted to stdout as well as configured capture location
Unexpected output: 
	- Make sure you are root before capturing traffic
	- Make sure a valid device is defined for the netcap --interface 
	option. If in doubt of the available interfaces that can be 
	captured from, run: sudo ./netcap --list-interfaces
	- Ensure there is traffic on the interface to capture (you 
	can use a tool like "tcpdump", nmap, or "nc" to test)

3. Test learn mode 

./netcap --learn --capture-file </path/to/capture-file> --learn-file </path/to/learn-file>

Expected output: 
	Traffic should be read from the configured locations for captured 
	traffic and learned data should be written to the configured 
	location for learned traffic
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
modified for "production" use. This is because it should be kept as a reference as it contains other documentation.

5. Test monitor mode: 

5a. Start server (NON daemon)

./netcap --monitor --server <host> <port> --notify out=<path/to/notify-file> --cache-file </path/to/cache-file> --cache-key-dst --log=server </path/to/server-log-file> --stdout --packet-count 10

Expected output: 
	netcap should start listening on <host> and <port> and display information 
	to stdout
	Log files should be created in their configured locations as provided 
	above
	The server should dump the cache and create a notification file (as 
	specified above) after 10 unique packets
Unexpected output:
	- Make sure host and port are correct
	- You will not receive alerts until you proceed with 5b 

5b. Start client (NON daemon)

./netcap --monitor --client <host> <port> --interface <device> --promiscuous --learn-file </path/to/learn-file> --log=client out=<path/to/client-log-file> --packet-count 1000 --unique --stdout

Expected output: 
	netcap should start listening on <host> and <port> and display information 
	to stdout
	Log files should be created in their configured locations as provided 
	above
	The client should cleanly exit after 1000 unique packets
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

./netcap --monitor --server <host> <port> --notify out=<path/to/notify-file> --cache-file </path/to/cache-file> --cache-key-dst --log=server </path/to/server-log-file> --packet-count <count> --daemon

** NOTE: If you are not sure what count to use, keep what you tested with in 
step 5a or omit the option. You can always send a SIGUSR1 to dump the cache 
and build a notification
** NOTE: The process id can be found in the server log or you could look at 
the running processes to find it
** NOTE: You can tail the server log to keep status on the various ongoings

Client:

./netcap --monitor --client <host> <port> --interface <device> --promiscuous --learn-file </path/to/learn-file> --log=client out=<path/to/client-log-file> --packet-count 1000 --unique --daemon

** NOTE: If you are not sure what count to use, keep what you tested with in 
step 5b or omit the option. You can always send a SIGUSR1 to refresh the 
client, should you update the netcap learn file
** NOTE: The process id can be found in the client log or you could look at 
the running processes to find it
** NOTE: You can tail the client log to keep status on the various ongoings


7. Test client/server communication

Once server and client are running, generate some traffic. 

Use the learn file you created or the rules you modified in the default "sample.learn" file. Generate traffic to the destinations/ports you 
defined as unauthorized. Example:

You could port scan the server host 

sudo nmap -A -T4 -p<unauth-port,…> <IPv4-dst_addr>

Or, telnet to some unauthorized ports

telnet <IPv4-dst_addr> <unauth-port>

Expected output: 
	Should see data in client / server logs
	Should see the server dump its cache and generate a notification
	Should see the client stop (after <count> packets, if you specified the 
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
	