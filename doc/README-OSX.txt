===========================================================================
Purpose:
	This is for setting netcap to be loaded once at system startup on 
	OS X (requires 10.4 or higher).

Note:
	- Netcap should be installed and functional BEFORE performing 
	anything in this file.
	- It is unnecessary to use netcap's daemon mode to start the 
	client/server as launched will handle this for you.
	- It is advisable to NOT modify the original .plist files, should 
	you need to reply on them in the future.
	- For any further information on plist files, see plist(5) or the 
	following URL: http://developer.apple.com/macosx/launchd.html.
	- There are two .plist files (for the client: netcap-client.plist 
	and for the server: netcap-server.plist) that a user can rely on 
	in order to have netcap started upon system startup. If these 
	are in place, launchd will start netcap up in daemon mode for 
	you. The default plist files are configured with the most common 
	options. You will need to edit it accordingly using a tool such 
	as PlistEdit Pro (which is Apple's Property List Editor) or a 
	standard text editor in order to modify the XML.
===========================================================================

If you choose to use these files, follow the steps below:

1. Update the netcap client plist file and review the defaults that are 
included in this distribution. At a minimum, the following will need to be 
updated for your install of the client plist file:

A. 
Key: "Label"
String: "your-domain.netcap-client"

What to do: Replace "your-domain" with something like: com.your-company
For example, if your domain is "foobar.com", then change it to:
	
	com.foobar.netcap-client

B. 
Key: "Program"
String: "/path/to/netcap/netcap"

What to do: Replace "/path/to/netcap/" with the absolute path to where 
netcap is located. Ensure the netcap program is not excluded as part of 
the path. For example, if netcap is installed in the following location: 
"/Users/foobar/netcap/bin/", then set the string as: 
	
	/Users/foobar/netcap/bin/netcap

C. 
Key: "ProgramArguments" 
Array String: "server-address"

What to do: Replace "server-address" with the IP address of the 
listening server host or the hostname. For example if the server is running on your local network as "foobar" (192.168.0.20), then set the string as:

	Host: foobar
	-or-
	IP: 192.168.0.20

Note: If the server is running on the same host as the client, you can use 
"localhost", the local IP, or the loopback address such as:
	
	Local host (foobar): localhost
	Local IP: 192.168.0.20
	Loopback: 127.0.0.1

D. 
Key: "ProgramArguments" 
Array String: "server-port-number"

What to do: Replace "server-port-number" with the port number the netcap 
server will listen on. For example if the server will listen on port:
10000, then set the string as:

	10000

E. 
Key: "ProgramArguments" 
Array String: "ethernet-device"

What to do: Replace "ethernet-device" with the interface you wish netcap 
to capture traffic from. For example, if "en0" is the device, then set the 
string as:

	en0

Note: 
To determine what interfaces may be captured, run: 

# ./netcap --list-interfaces 

If you do not get any interface output, make sure you are running the command with root privileges (e.g., sudo). The first device in the list is 
the default that netcap will use if "--interface" is not used. If the 
default device is valid to capture from, you can remove the "--interface" 
and the "ethernet-device" string references from the plist file as netcap 
will capture from the default device so the "--interface" option is not 
needed.

You can also run the following standard *nix command to get a list of devices (Note: you may need to have root privileges): 

# ifconfig

F. 
Key: "ProgramArguments" 
Array String: "/path/to/netcap-config/netcap.config"

What to do: Replace "/path/to/netcap-config/" with the absolute path to where netcap's configuration file is located. For example, if netcap's 
configuration file is located in "/Users/foobar/netcap/etc/", then set the 
string as: 
	
	/Users/foobar/netcap/etc/netcap.config

G. 
Key: "StandardErrorPath" 
String: "/path/to/netcap-stderr-file/netcap-client.stderr"

What to do: Replace "/path/to/netcap-stderr-file/" with the absolute path 
to where launchd should direct netcap's standard error stream. For 
example, if you want launchd to redirect all of netcap's standard error 
stream to "/Users/foobar/netcap/var/log/" and place it in the file 
"netcap-client.stderr", then set the string as: 
	
	/Users/foobar/netcap/var/log/netcap-client.stderr

H. 
Key: "StandardOutPath" 
String: "/path/to/netcap-stdout-file/netcap-client.stdout"

What to do: Replace "/path/to/netcap-stdout-file/" with the absolute path 
to where launchd should direct netcap's standard output stream. For example, if you want launchd to redirect all of netcap's standard output 
stream to "/Users/foobar/netcap/var/log/" and place it in the file 
"netcap-client.stdout", then set the string as: 
	
	/Users/foobar/netcap/var/log/netcap-client.stdout

===========================================================================

2. Update the netcap server plist file and review the defaults that are 
included in this distribution. At a minimum, the following will need to be 
updated for your install of the server plist file:

A. 
Key: "Label"
String: "your-domain.netcap-server"

What to do: Replace "your-domain" with something like: com.your-company
For example, if your domain is "foobar.com", then change it to:
	
	com.foobar.netcap-server

B. 
Key: "Program"
String: "/path/to/netcap/netcap"

What to do: Replace "/path/to/netcap/" with the absolute path to where 
netcap is located. Ensure the netcap program is not excluded as part of 
the path. For example, if netcap is installed in the following location: 
"/Users/foobar/netcap/bin/", then set the string as: 
	
	/Users/foobar/netcap/bin/netcap

C.
Key: "ProgramArguments" 
Array String: "server-address"

What to do: Replace "server-address" with the IP address of the 
listening server host or the hostname. For example if the server is running on your local network as "foobar" (192.168.0.20), then set the string as:

	Host: foobar
	-or-
	IP: 192.168.0.20

Note: If the server is running on the same host as the client, you can use 
"localhost", the local IP, or the loopback address such as:
	
	Local host (foobar): localhost
	Local IP: 192.168.0.20
	Loopback: 127.0.0.1

D. 
Key: "ProgramArguments" 
Array String: "server-port-number"

What to do: Replace "server-port-number" with the port number the netcap 
server will listen on. For example if the server will listen on port 
10000, then set the string as:

	10000

E. 
Key: "ProgramArguments" 
Array String: "/path/to/netcap-config/netcap.config"

What to do: Replace "/path/to/netcap-config/" with the absolute path to 
where netcap's configuration file is located. For example, if netcap's 
configuration file is located in "/Users/foobar/netcap/etc/", then set the 
string as: 
	
	/Users/foobar/netcap/etc/netcap.config

F. 
Key: "StandardErrorPath" 
String: "/path/to/netcap-stderr-file/netcap-server.stderr"

What to do: Replace "/path/to/netcap-stderr-file/" with the absolute path 
to where launchd should direct netcap's standard error stream. For 
example, if you want launchd to redirect all of netcap's standard error 
stream to "/Users/foobar/netcap/var/log/" and place it in the file 
"netcap-server.stderr", then set the string as: 
	
	/Users/foobar/netcap/var/log/netcap-server.stderr

H. 
Key: "StandardOutPath" 
String: "/path/to/netcap-stdout-file/netcap-server.stdout"

What to do: Replace "/path/to/netcap-stdout-file/" with the absolute path 
to where launchd should direct netcap's standard output stream. For 
example, if you want launchd to redirect all of netcap's standard output stream to "/Users/foobar/netcap/var/log/" and place it in the file 
"netcap-server.stdout", then set the string as: 
	
	/Users/foobar/netcap/var/log/netcap-server.stdout

===========================================================================

3. Rename your copy of the plist files 

A. Rename "netcap-client.plist" to the same value that you set in step 1A.
B. Rename "netcap-server.plist" to the same value that you set in step 2A.

===========================================================================

4. To ensure netcap is started automatically, place the netcap client and 
server .plist files in: 

/Library/LaunchDaemons/

===========================================================================

5. Ensure they are owned by root and set the group to wheel:

# chown root:wheel <plist-file>

===========================================================================

6. Ensure the permissions bits are set:

# chmod 640 <plist-file>
