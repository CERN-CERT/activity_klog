#include <linux/module.h>
#include <linux/slab.h>
#include "connection.h"
#include "whitelist.h"

#ifndef INET6_ADDRSTRLEN
	#define INET6_ADDRSTRLEN 48
#endif

struct connection
{
	int port;
	char ip[INET6_ADDRSTRLEN + 2];
	char executable[MAX_ABSOLUTE_EXEC_PATH + 1];
};

int string_contains(const char *string, char ch, int limit)
{
	if(string == NULL)
	{
		return 0;
	}
	
	while(*string != '\0' && limit > 0)
	{
		if(*string == ch)
		{
			return 1;
		}
		string++;
		limit--;
	}
	
	return 0;
}

int valid_connection_string(const char *connection_string)
{
	//TODO 

	return 1;
}

struct connection *initialize_connection(void)
{
	struct connection *new_connection = NULL;
	
	new_connection = kmalloc(sizeof(struct connection), GFP_ATOMIC);
	
	if(new_connection == NULL)
	{
		return NULL;
	}
	
	memset(new_connection->executable, '\0', sizeof(new_connection->executable));
	memset(new_connection->ip, '\0', sizeof(new_connection->ip));
	new_connection->port = NO_PORT;
	
	return new_connection;
}

/*Initialize a struct connection from a given string.
 *The string must have the format "/absolute/path|i<ip>|p<port number>"
 *
 *i.e. "/usr/bin/sshd|i<127.128.0.0>|p<22>"
 *     "/usr/bin/sshd|i<127.128.0.0>"
 *     "/usr/bin/sshd|p<22>"
 *     "/usr/bin/sshd"
 *
 *The '<' and '>' can be ignored, they are supported just for visual reasons.
 *
 *The implementation contains a little bit of magic. Sorry! Panos
 */
 
struct connection *initialize_connection_from_string(const char *connection_string)
{
	int i;
	const char *ch;
	struct connection *new_connection = NULL;

	if(connection_string == NULL)
	{
		goto out_fail;
	}

	if(!valid_connection_string(connection_string))
	{
		goto out_fail;
	}
	
	new_connection = initialize_connection();
	
	if(new_connection == NULL)
	{
		goto out_fail;
	}
	
	/*First field has to be a path*/
	
	i = 0;
	ch = connection_string;

	while(*ch != FIELD_SEPARATOR && *ch != '\0')
	{
		new_connection->executable[i] = *ch;
		ch++;
		i++;
	
		/*Too big path, fail to whitelist*/
	
		if(i > MAX_ABSOLUTE_EXEC_PATH)
		{
			goto out_fail;
		}
	}
	
	new_connection->executable[i] = '\0';

	/*Skip the field separator, if any*/

	if(*ch == FIELD_SEPARATOR)
	{
		ch++;
	}
		
	/*Case of next field being an ip address*/
	
	if(*ch == 'i')
	{	
		/*If the ip is IPv6, add square brackets in the beginning and in the end
		 *This is done in order to make right comparison between ipv6 addresses.
		 *The inet_utils functions return ipv6 addresses within square brackets.
		 */
		
		int ipv6 = string_contains(ch, ':', INET6_ADDRSTRLEN);
	
		ch++;
		
		/*Skip '<', if any*/
		
		if(*ch == '<')
		{
			ch++;
		}
	
		i = 0;
		
		if(ipv6)
		{
			/*Add opening square bracket*/

			new_connection->ip[0] = '[';
			i++;
		}
		
		while(*ch != '>' && *ch != '\0' && *ch != FIELD_SEPARATOR)
		{
			new_connection->ip[i] = *ch;
			ch++;
			i++;
	
			/*Too big ip, fail to whitelist*/
	
			if(i > INET6_ADDRSTRLEN)
			{
				goto out_fail;
			}
		}
	
		if(ipv6)
		{
			/*Add closing square bracket*/
			
			new_connection->ip[i] = ']';
			i++;
		}
	
		new_connection->ip[i] = '\0';
		ch++;		
	}

	/*Skip the field separator, if any*/

	if(*ch == FIELD_SEPARATOR)
	{
		ch++;
	}

	/*Case of next field being a port number*/

	if(*ch == 'p')
	{
		int base = 1;
		const char *number_start;

		ch++;
	
		/*Skip '<', if any*/
		
		if(*ch == '<')
		{
			ch++;
		}

		number_start = ch;

		/*Go to end of number*/
		
		while(*ch != '>' && *ch != '\0')
			ch++;
		ch--;
		
		new_connection->port = 0;
		
		while(ch >= number_start)
		{
			new_connection->port += (*ch - '0') * base;
			base *= 10;
			ch--;
		}

		/*Overflow check*/
		
		if(new_connection->port < 0)
		{
			goto out_fail;
		}
	}

	return new_connection;

out_fail:

	if(new_connection)
	{
		kfree(new_connection);
	}

	return NULL;
}

int connection_matches_attributes(const struct connection *connection, const char *path, const char *ip, const int port)
{
	if(unlikely(connection == NULL || path == NULL || ip == NULL))
	{
		return 0;
	}
	
	if(strncmp(connection->executable, path, MAX_ABSOLUTE_EXEC_PATH) != 0)
	{
		/*Executable path missmatch*/
		
		return 0;
	}

	if(connection->ip[0] != '\0' && ip[0] != '\0')
	{
		if(strncmp(connection->ip, ip, INET6_ADDRSTRLEN) != 0)
		{
			/*IPs were given and didn't match*/

			return 0;
		}
	}

	if(connection->port != NO_PORT && port != NO_PORT)
	{
		if(connection->port != port)
		{
			/*Ports given and missmatched*/
			
			return 0;
		}
	}

	return 1;
}

int connections_are_equal(const struct connection *connection1, const struct connection *connection2)
{
	if(connection1 == NULL || connection2 == NULL)
	{
		return 0;
	}

	return connection_matches_attributes(connection1, connection2->executable, connection2->ip, connection2->port);
}

void destroy_connection(struct connection *connection)
{
	if(connection)
	{
		kfree(connection);
	}
}
