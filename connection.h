#ifndef __CONNECTION__
#define __CONNECTION__

#define NO_PORT -1

#define FIELD_SEPARATOR '|'

struct connection;

struct connection *initialize_connection_from_string(const char *connection_string);

int connections_are_equal(const struct connection *connection1, const struct connection *connection2);

int connection_matches_attributes(const struct connection *connection, const char *path, const char *ip, const int port);

void destroy_connection(struct connection *connection);

#endif
