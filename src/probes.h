#ifndef __NETLOG_PROBES__
#define __NETLOG_PROBES__

#define PROBES_NUMBER 6

#define PROBE_TCP_CONNECT 1
#define PROBE_TCP_ACCEPT  2
#define PROBE_TCP_CLOSE   3
#define PROBE_UDP_CONNECT 4
#define PROBE_UDP_BIND    5
#define PROBE_UDP_CLOSE   6

int plant_probe(u32);
void unplant_probe(u32);
void unplant_all(void);

#endif /* __NETLOG_PROBES__ */
