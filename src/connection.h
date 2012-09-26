#ifndef __CONNECTION__
#define __CONNECTION__

#define MAX_LENGTH_OF_CONNECTION_STRING (5 + INET6_ADDRSTRLEN + 2 + MAX_ABSOLUTE_EXEC_PATH + 1 + 2 + 1)

#define NO_PORT -1

#define FIELD_SEPARATOR '|'

struct connection;

struct connection *initialize_connection_from_string(const char *connection_string);

int connections_are_equal(const struct connection *connection1, const struct connection *connection2);

int connection_matches_attributes(const struct connection *connection, const char *path, const char *ip, const int port);

void destroy_connection(struct connection *connection);

#endif
