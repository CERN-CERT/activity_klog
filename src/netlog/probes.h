#ifndef __NETLOG_PROBES__
#define __NETLOG_PROBES__

#define PROBES_NUMBER 6

#define PROBE_TCP_CONNECT 0
#define PROBE_TCP_ACCEPT  1
#define PROBE_TCP_CLOSE   2
#define PROBE_UDP_CONNECT 3
#define PROBE_UDP_BIND    4
#define PROBE_UDP_CLOSE   5

int plant_probe(u32);
void unplant_probe(u32);
void unplant_all(void);
int probe_status(u32);

#endif /* __NETLOG_PROBES__ */
