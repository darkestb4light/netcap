===========================================================================
Purpose:
	This is for setting netcap to be loaded once at system startup on 
	FreeBSD (7.x or higher).

Note:
	- Netcap should be installed and functional BEFORE performing 
	anything in this file.
	- Should work with any standard *nix system to start netcap upon 
	loading. However, these were only tested (in this distribution 
	with FreeBSD.
	- You may have to change the destination path if the system will 
	expect the "startup" scripts to reside in another location. To 
	validate, see rc(8).
	- There are two shell scripts that a user can rely on in order to 
	have netcap started upon system startup: nc-start-client-onload 
	(starts the client) and nc-start-server-onload (starts the server).
	- It is advisable to NOT modify the original scripts, should 
	you need to reply on them in the future.
===========================================================================

If you choose to use these startup files, follow the steps below:

1. Update the netcap client script:

A. Set command target

Change the line from: 
	
	command="/path/to/netcap/netcap" 

To: The absolute path where netcap resides (ensure it includes the 
netcap program name in the path). For example, if netcap was installed to: 
/usr/local/netcap/, then change the line to:

	command="/usr/local/netcap/bin/netcap"

B. Set command arguments

Change the line from:

	command_args="--monitor --client 
			<server-address> <server-port-number> 
			--interface <ethernet-device> 
			--promiscuous 
			--daemon 
			--Config </path/to/netcap-config/netcap.config>" 

Note: 
- The above line is split on multiple lines ONLY for readability - When 
modified, it MUST be on one line. 
- Enter arguments/options EXACTLY as you would on the command line. Now, 
simply replace the input between the double quotes following:
command_args= (i.e., command_args="<arguments and options here>".
- If an option listed above is not desired, remove it when modifying. For 
example, you may not wish for the interface to be started in promiscuous 
mode (i.e., remove --promiscuous).
- If an option is missing, simply add it. For example, you may wish for 
the client to filter for certain captured traffic (i.e., see --regex 
option).

To: What is required to start the client. This script starts the client with the 
most common options. The minimum arguments/options that MUST be changed are: 
	- <server-address> 
	- <server-port-number> 
	- <ethernet-device>
	- </path/to/netcap-config/netcap.config>

For example, to have the client connect to a listening netcap server with 
the following parameters: 
	- Server is running on a remote host: foobar
	- Server will be listening on port: 10000
	- Client will listen for traffic on interface: bridge0 
	- Client will try to start the interface in promiscuous mode
	- Client will filter ALL traffic unless it matches the following 
	traffic expression: 
		Source/Destination of: 
			192.168.10.125, .128, .44, .45, and .49
		Port: 
			22 (SSH), 137/139 (NetBios)
	- Client will start up as a daemon process
	- Netcap configuration file is located: /usr/local/netcap/etc/

Note: The following line is split on multiple lines ONLY for readability. When modified, 
it MUST be on one line:

	command_args="--monitor --client 
			foobar 10000 
			--interface bridge0 
			--promiscuous
			--regex 
			'192.168.10.(12[58]|4[459]):(22|13[79])\b'
			--daemon 
			--Config /usr/local/netcap/etc/netcap.config"

===========================================================================

2. Update the netcap server script:

A. Set command target

Change the line from: 
	
	command="/path/to/netcap/netcap" 

To: The absolute path where netcap resides (ensure it includes the 
netcap program name in the path). For example, if netcap was installed to: 
/usr/local/netcap/, then change the line to:

	command="/usr/local/netcap/bin/netcap"

B. Set command arguments

Change the line from:

	command_args="--monitor --client 
			<server-address> <server-port-number>
			--sort-cache-date 
			--cache-key-dst 
			--log=server 
			--notify
		 	--daemon 
			--Config </path/to/netcap-config/netcap.config>" 

Note: 
- The above line is split on multiple lines ONLY for readability - When 
modified, it MUST be on one line. 
- Enter arguments/options EXACTLY as you would on the command line. Now, 
simply replace the input between the double quotes following:
command_args= (i.e., command_args="<arguments and options here>".
- If an option listed above is not desired, remove it when modifying. For 
example, you may not wish for server to notify (i.e., remove --notify)
- If an option is missing, simply add it. For example, you may wish for 
the server to dump its cache after capturing a certain number of packets 
(i.e., see --packet-count option).

To: What is required to start the server. This script starts the client with the most 
common options. The minimum arguments/options that MUST be changed are: 
	- <server-address> 
	- <server-port-number> 
	- </path/to/netcap-config/netcap.config>

For example, to have the client connect to a listening netcap server with 
the following parameters: 
	- Server is running on host: foobar
	- Server will be listening on port: 10000
	- Server will sort by the packet date first seen (as notified by 
	a netcap client)
	- Server will group all source IP traffic by destination IP and 
	port
	- Server will log to its default log file
	- Server will create notification messages (upon dumping its 
	cache)
	- Server will start as a daemon process
	- Netcap configuration file is located: /usr/local/netcap/etc/

Note: The following line is split on multiple lines ONLY for readability. When modified, 
it MUST be on one line:

	command_args="--monitor --server 
			foobar 10000
			--sort-cache-date 
			--cache-key-dst 
			--log=server 
			--notify
			--daemon 
			--Config /usr/local/netcap/etc/netcap.config"

===========================================================================

3. Place the startup scripts listed below in: /usr/local/etc/rc.d/

A. nc-start-client-onload (runs the client command line)
B. nc-start-server-onload (runs the server command line)

===========================================================================

4. Script should be owned by root
# chown root /usr/local/etc/rc.d/<script>

===========================================================================

5. Script should be readable/executable:
# chmod /usr/local/etc/rc.d/<script>
