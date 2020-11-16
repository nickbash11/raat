#include "raat.h"

#define DEFAULT_PRIORITY 33333
#define REGULAR_PRIORITY 30000
#define MIN_ALFRED_LENGTH 50
#define MAX_ALFRED_LENGTH 433
#define NODES_MAX 255

void errCatchFunc(FILE *pipe, int point);

static int nodes_counter = 0;

static pull *nodes_by_rt_table_id = NULL, *nodes_by_mac = NULL;

void flushRulesRoutes(void)
{
	char line[1000] = {0x0};
	char defaultPriorityBuf[10] = {0x0};
	char regularPriorityBuf[10] = {0x0};
	char lineBuf[100] = {0x0};
	char ip_cmd[200] = {0x0};
	char *p_lineBuf;

	// convert integer to string
	sprintf(defaultPriorityBuf, "%d", DEFAULT_PRIORITY);
	sprintf(regularPriorityBuf, "%d", REGULAR_PRIORITY);

	// open pipe for reading
	FILE* rules_read0 = popen("/sbin/ip rule", "r");
	errCatchFunc(rules_read0, 0);

	// here we get numbers of tables for regular routes and flush them
	// also we flush rules
	while(fgets(line, sizeof(line), rules_read0) != NULL)
	{
		if(strstr(line, regularPriorityBuf))
		{
			snprintf(lineBuf, strlen(line)-strlen(regularPriorityBuf), "%s", line+strlen(regularPriorityBuf)+2);

			p_lineBuf = strtok(line, " ");
			for(int i = 0; i < 5; i++)
			{
				p_lineBuf = strtok(NULL, " ");
			}
			sprintf(ip_cmd, "/sbin/ip route flush table %s", p_lineBuf);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* flush0 = popen(ip_cmd, "w");
			errCatchFunc(flush0, 1);
			pclose(flush0);

			sprintf(ip_cmd, "/sbin/ip rule del %s", lineBuf);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* flush1 = popen(ip_cmd, "w");
			errCatchFunc(flush1, 2);
			pclose(flush1);
		}
	}
	//close pipe
	pclose(rules_read0);

	// open pipe for reading
	FILE* rules_read1 = popen("/sbin/ip rule", "r");
	errCatchFunc(rules_read1, 3);

	// here we get numbers of tables for default routes and flush them
	// also we flush rules
	while(fgets(line, sizeof(line), rules_read1) != NULL)
	{
		if(strstr(line, defaultPriorityBuf))
		{
			snprintf(lineBuf, strlen(line)-strlen(defaultPriorityBuf), "%s", line+strlen(defaultPriorityBuf)+2);

			p_lineBuf = strtok(line, " ");
			for(int i = 0; i < 3; i++)
			{
				p_lineBuf = strtok(NULL, " ");
			}
			sprintf(ip_cmd, "/sbin/ip route flush table %s", p_lineBuf);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* flush0 = popen(ip_cmd, "w");
			errCatchFunc(flush0, 4);
			pclose(flush0);

			sprintf(ip_cmd, "/sbin/ip rule del %s", lineBuf);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* flush1 = popen(ip_cmd, "w");
			errCatchFunc(flush1, 5);
			pclose(flush1);
		}
	}
	// close pipe
	pclose(rules_read1);
}

void getRoutes(push *snd, pull *rcv, flags *f)
{
	int num, invalid;
	char macBuf[18] = {0x0};
	char payloadBuf[1000] = {0x0};
	char payloadBufValidate[1000] = {0x0};
	char routesAnnounce[1000] = {0x0};
	char line[1000] = {0x0};
	char ip_cmd[100] = {0x0};
	char *p_payloadGap;
	char *p_route;
	char *p_timestamp;
	char alfred_cmd[50] = {0x0};

	sprintf(alfred_cmd, "/usr/sbin/alfred -r %d", f->dataType);
	FILE* alfred_pipe = popen(alfred_cmd, "r");
	errCatchFunc(alfred_pipe, 6);

	while(fgets(line, sizeof(line), alfred_pipe) != NULL)
	{
		// skip its own record
		if(strstr(line, snd->batmanAddr))
		{
			continue;
		}

		// ignore too short or too long lines
		if(strlen(line) < MIN_ALFRED_LENGTH || strlen(line) > MAX_ALFRED_LENGTH)
		{
			continue;
		}

		// copy string with mac to a buffer
		snprintf(macBuf, 18, "%s", line+3);

		// copy string with payload info to a buffer
		snprintf(payloadBuf, strlen(line+24)-4, "%s", line+24);

		// copy string with payload info to a validation buffer
		snprintf(payloadBufValidate, strlen(line+24)-4, "%s", line+24);

		// validate input data for correct containing
		invalid = 0;
		if(payloadValidator(payloadBufValidate) != 0)
		{
			invalid = 1;
		}

		// add a new one node
		HASH_FIND(hh2, nodes_by_mac, macBuf, strlen(macBuf), rcv);
		if(rcv == NULL)
		{
			// if detected invalidations
			if(invalid == 1)
			{
				continue;
			}

			if(nodes_counter >= NODES_MAX)
			{
				continue;
			}

			// +1 to nodes
			nodes_counter++;

			// generate a pseudo random number
			while(1)
			{
				num = rand() % 699 + 300;
				HASH_FIND(hh1, nodes_by_rt_table_id, &num, sizeof(num), rcv);
				if(rcv == NULL)
				{
					break;
				}
			}

			// allocate and initialize pointers to the structure
			rcv = (pull *)malloc(sizeof *rcv);

			// clear struct before using
			memset(rcv, 0, sizeof(*rcv));

			// add items and create hashes
			strcpy(rcv->mac, macBuf);
			rcv->rt_table_id = num;
			HASH_ADD(hh1, nodes_by_rt_table_id, rt_table_id, sizeof(int), rcv);
			HASH_ADD(hh2, nodes_by_mac, mac, strlen(rcv->mac), rcv);

			// send info about
			syslog(LOG_INFO, "%s is a new node", rcv->mac);

			// split payload string, the first piece (is unix timestamp)
			p_payloadGap = strtok(payloadBuf, "*");

			// split payload string, other pieces (routes)
			int r = -2;
			while(p_payloadGap != NULL)
			{
				if(r == -2)
				{
					// first string with unix timestamp
					rcv->node_timestamp = strtol(p_payloadGap, &p_timestamp, 10);
					rcv->node_timestamp_previous = rcv->node_timestamp;
				}
				else if(r == -1)
				{
					// copy ipv4 address
					strcpy(rcv->ipv4, p_payloadGap);
				}
				else
				{
					if(strcmp(p_payloadGap, "none") != 0)
					{
						// add routes
						addRoute(rcv, p_payloadGap, ip_cmd);

						// write routes to structure
						strcat(rcv->routes, p_payloadGap);
						strcat(rcv->routes, "*");
					}
					else
					{
						// copy "none" to previous routes
						strcat(rcv->routes, p_payloadGap);
						strcat(rcv->routes, "*");
						break;
					}
				}
				p_payloadGap = strtok(NULL, "*");
				r++;
			}
		}
		else
		{
		// the item exists

			// if the node contains an invalid data then delete all and forget about it
			if(invalid == 1)
			{
				// send info about delete
				syslog(LOG_INFO, "%s is invalid", rcv->mac);

				p_route = strtok(rcv->routes, "*");
				while(p_route != NULL)
				{
					if(strcmp(p_route, "none") != 0)
					{
						deleteRoute(rcv, p_route, ip_cmd);
					}					
					p_route = strtok(NULL, "*");
				}

				// -1 to nodes
				nodes_counter--;

				// freeing memory
				HASH_DELETE(hh2, nodes_by_mac, rcv);
				HASH_DELETE(hh1, nodes_by_rt_table_id, rcv);
				free(rcv);

				// continue to the next iteration
				continue;
			}

			// split payload string, the first piece (is unix timestamp)
			p_payloadGap = strtok(payloadBuf, "*");

			// split payload string, other pieces (routes)
			int r = -2;
			while(p_payloadGap != NULL)
			{
				if(r == -2)
				{
					// first string with unix timestamp
					rcv->node_timestamp = strtol(p_payloadGap, &p_timestamp, 10);

					// if the timestamp status is not updated - no point to update routes, just skip
					if(rcv->node_timestamp == rcv->node_timestamp_previous)
					{
						rcv->breakup_count++;

						// if breakup more than BREAKUP then delete all the rules and routes
						if(rcv->breakup_count == f->breakUp)
						{
							syslog(LOG_INFO, "%s is dead now", rcv->mac);

							// delete all routes and rules
							p_route = strtok(rcv->routes, "*");
							while(p_route != NULL)
							{
								if(strcmp(p_route, "none") != 0)
								{
									deleteRoute(rcv, p_route, ip_cmd);
								}
								p_route = strtok(NULL, "*");
							}
							memset(rcv->routes, 0, sizeof(rcv->routes));
						}
						goto skip;
					}

					// the node is back from dead
					if(rcv->breakup_count >= f->breakUp)
					{
						syslog(LOG_INFO, "%s is alive now", rcv->mac);
					}

					rcv->breakup_count = 0;
					rcv->node_timestamp_previous = rcv->node_timestamp;
				}
				else if(r == -1)
				{
					// ipv4 address has already gotten, do nothing
				}
				else
				{
					// checking for what routes need to add
					if(strstr(rcv->routes, p_payloadGap) == NULL)
					{
						if(strcmp(p_payloadGap, "none") != 0)
						{
							addRoute(rcv, p_payloadGap, ip_cmd);
						}
					}

					// put the routes to check what to delete further
					strcat(routesAnnounce, p_payloadGap);
					strcat(routesAnnounce, "*");
				}
				p_payloadGap = strtok(NULL, "*");
				r++;
			}

			// checking for what routes need to delete
			p_route = strtok(rcv->routes, "*");
			while(p_route != NULL)
			{
				if(strstr(routesAnnounce, p_route) == NULL)
				{
					if(strcmp(p_route, "none") != 0)
					{
						deleteRoute(rcv, p_route, ip_cmd);
					}
				}
				p_route = strtok(NULL, "*");
			}

			// set routes variable to zero
			memset(rcv->routes, 0, sizeof(rcv->routes));
			// keep routes for the next cycle
			strcat(rcv->routes, routesAnnounce);
		}
		skip:;

		// reset every time
		routesAnnounce[0] = '\0';
	}
	pclose(alfred_pipe);
}

void deleteRoute(pull *rcv, char *p_route, char ip_cmd[])
{
	sprintf(ip_cmd,"/sbin/ip route del %s via %s table %d", p_route, rcv->ipv4, rcv->rt_table_id);
	syslog(LOG_INFO, "%s", ip_cmd);
	FILE *del0 = popen(ip_cmd, "w");
	errCatchFunc(del0, 7);
	pclose(del0);

	if(strcmp(p_route, "default") == 0)
	{
		sprintf(ip_cmd, "/sbin/ip rule del from all priority %d table %d", DEFAULT_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE *del1 = popen(ip_cmd, "w");
		errCatchFunc(del1, 8);
		pclose(del1);
	}
	else
	{
		sprintf(ip_cmd, "/sbin/ip rule del from all to %s priority %d table %d", p_route, REGULAR_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE *del2 = popen(ip_cmd, "w");
		errCatchFunc(del2, 9);
		pclose(del2);
	}
}

void addRoute(pull *rcv, char *p_route, char ip_cmd[])
{
	sprintf(ip_cmd, "/sbin/ip route replace %s via %s table %d", p_route, rcv->ipv4, rcv->rt_table_id);
	syslog(LOG_INFO, "%s", ip_cmd);
	FILE *add0 = popen(ip_cmd, "w");
	errCatchFunc(add0, 10);
	pclose(add0);

	if(strcmp(p_route, "default") == 0)
	{
		sprintf(ip_cmd, "/sbin/ip rule add from all priority %d table %d", DEFAULT_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE* add1 = popen(ip_cmd, "w");
		errCatchFunc(add1, 11);
		pclose(add1);
	}
	else
	{
		sprintf(ip_cmd, "/sbin/ip rule add from all to %s priority %d table %d", p_route, REGULAR_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE* add2 = popen(ip_cmd, "w");
		errCatchFunc(add2, 12);
		pclose(add2);
	}
}

void removeExpired(pull *rcv, flags *f)
{
	int flag;
	char line[1000] = {0x0};
	char ip_cmd[100] = {0x0};
	char alfred_cmd[50] = {0x0};
	char *p_route;

	sprintf(alfred_cmd, "/usr/sbin/alfred -r %d", f->dataType);

	for(rcv=nodes_by_mac; rcv != NULL; rcv=rcv->hh2.next)
	{
		FILE* alfred_pipe = popen(alfred_cmd, "r");
		errCatchFunc(alfred_pipe, 13);

		flag = 0;
		while(fgets(line, sizeof(line), alfred_pipe) != NULL)
		{
			if(strstr(line, rcv->mac) != NULL)
			{
				flag++;
			}
		}
		if(flag == 0)
		{
			// delete route table and hash as expired
			sprintf(ip_cmd, "/sbin/ip route flush table %d", rcv->rt_table_id);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* flush0 = popen(ip_cmd, "w");
			errCatchFunc(flush0, 14);
			pclose(flush0);

			// send info about delete
			syslog(LOG_INFO, "%s does not exist anymore", rcv->mac);

			p_route = strtok(rcv->routes, "*");
			while(p_route != NULL)
			{
				if(strstr(p_route, "default"))
				{
					sprintf(ip_cmd, "/sbin/ip rule del from all priority %d lookup %d", DEFAULT_PRIORITY, rcv->rt_table_id);
				}
				else
				{
					sprintf(ip_cmd, "/sbin/ip rule del from all to %s priority %d lookup %d", p_route, REGULAR_PRIORITY, rcv->rt_table_id);
				}
				syslog(LOG_INFO, "%s", ip_cmd);
				FILE* flush1 = popen(ip_cmd, "w");
				errCatchFunc(flush0, 15);
				pclose(flush1);
				p_route = strtok(NULL, "*");
			}


			// -1 to nodes
			nodes_counter--;

			// delete and free an unexisting node
			HASH_DELETE(hh2, nodes_by_mac, rcv);
			HASH_DELETE(hh1, nodes_by_rt_table_id, rcv);
			free(rcv);

		}
		pclose(alfred_pipe);
	}
}

int payloadValidator(char line[])
{
	int i, flag, defflag, count;
	long timestamp;
	char *p_timestamp;
	char *p_lineBuf;
	char netmaskBuf[32];
	struct sockaddr_in sa;

	i = -2;
	flag = 0;
	defflag = 0;

	p_lineBuf = strtok(line, "*");
	while(p_lineBuf != NULL)
	{
		if(i == -2)
		{
			// check if the string contains 10 symbols
			if(strlen(p_lineBuf) == 10)
			{
				// check that it is really the unix timestamp
				// convert the string to long type
				timestamp = strtol(p_lineBuf, &p_timestamp, 10);
				count = 0;
				while (timestamp != 0)
				{
					timestamp /= 10;
					++count;
				}
				if(count != 10)
				{
					return -1;
				}
			}
			else
			{
				return -1;
			}
		}
		else if(i == -1)
		{
			// if this is an ip address
			if(inet_pton(AF_INET, p_lineBuf, &(sa.sin_addr)) != 1)
			{
				return -1;
			}
		}
		else
		{
			// if there is "none" then the next data is incorrect
			if(i == 0 && strcmp(p_lineBuf, "none") == 0)
			{
				flag = 1;
			}
			// the data is incorrect
			else if(flag == 1 && p_lineBuf != NULL)
			{
				return -1;
			}
			// if the default record occurs more than one time
			else if(strcmp(p_lineBuf, "default") == 0)
			{
				defflag++;
				if(defflag > 1)
				{
					return -1;
				}
			}
			// if this is not an ip address
			else if(strcmp(p_lineBuf, "default") != 0)
			{
				snprintf(netmaskBuf, strlen(p_lineBuf)-2, "%s", p_lineBuf);
				if(inet_pton(AF_INET, netmaskBuf, &(sa.sin_addr)) != 1)
				{
					return -1;
				}
			}
		}
		p_lineBuf = strtok(NULL, "*");
		i++;
	}
	return 0;
}

// catch for errors
void errCatchFunc(FILE *pipe, int point)
{
	if(pipe == NULL)
	{
		syslog(LOG_ERR, "Pull point %d", point);
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(-1);
	}
}

