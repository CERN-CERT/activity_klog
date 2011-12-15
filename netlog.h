#ifndef __NETLOG__
#define __NETLOG__

#define CONNECT_PROBE_FAILED -1
#define ACCEPT_PROBE_FAILED -2
#define SHUTDOWN_PROBE_FAILED -3
#define BIND_PROBE_FAILED -4 

#define PROBE_UDP 0
#define PROBE_CONNECTION_CLOSE 1

#define MAX_ACTIVE 100

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Panos Sakkos <panos.sakkos@cern.ch>");
MODULE_DESCRIPTION("Logs process name, pid, uid, source ip, source port number,\
	 	    destination ip and destination portnumber for every TCP connection.\
	 	    Also logs connection close and UDP binds");

#endif
