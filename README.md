# netcap

A network host to host discovery tool with the intent to: 1.) Capture 2.) Learn 3.) Monitor (and notify)

	==================
	OVERVIEW OF NETCAP
	==================

Netcap was written (currently in PERL) to be a network host to host discovery tool. 
Its purpose is the following:

1. Capture network packets in order to specify what is "normal" traffic
2. Learn from previously captured traffic and determine what is "normal" 
3. Monitor subsequent network traffic and alert when traffic is not 
"normal" (i.e., unauthorized or unknown).

It does NOT (currently) prevent traffic from occurring on the network. It 
is simply designed to alert when it sees traffic that is configured as 
unauthorized or unknown.

It is released under the GNU GENERAL PUBLIC LICENSE V3.
