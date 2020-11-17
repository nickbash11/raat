#include "raat.h"

// the define for default rule priority in iproute2 table
#define DEFAULT_PRIORITY 33333
// the define for regular rule priority in iproute2 table
#define REGULAR_PRIORITY 30000
// a minimal length of the string from alfred
#define MIN_ALFRED_LENGTH_STRING 50
// a maximum length of the string from alfred
#define MAX_ALFRED_LENGTH_STRING 433
// the max amount of nodes keeps in uthash
#define NODES_MAX 255
// the name of label for DEFAULT_LABEL presence on node
#define DEFAULT_LABEL "default"

void setDefaultRule(pull *rcv, flags *f, char ip_cmd[]);
void deleteRoute(pull *rcv, char *p_route, char ip_cmd[]);
void addRoute(pull *rcv, char *p_route, char ip_cmd[]);
int payloadValidator(char line[]);
int getTQ(char *macAddr);
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
		if(strlen(line) < MIN_ALFRED_LENGTH_STRING || strlen(line) > MAX_ALFRED_LENGTH_STRING)
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
	// close alfred pipe
	pclose(alfred_pipe);

	// call a function to evaluate and set the default rule for default route	
	setDefaultRule(rcv, f, ip_cmd);
}

void setDefaultRule(pull *rcv, flags *f, char ip_cmd[])
{
	int tqTmp = 0;
	int suitableDefaultId = 0;
	int previousDefaultId = 0;

	int i = 0;
	// iterate every node
	for(rcv=nodes_by_mac; rcv != NULL; rcv=rcv->hh2.next)
	{
		// who was the previous default route
		if(rcv->isDefault == 1)
		{
			previousDefaultId = rcv->rt_table_id;
		}

		// find for default and set TQ variable if the default string was found
		rcv->tqDefault = 0;
		if(strstr(rcv->routes, DEFAULT_LABEL) && rcv->breakup_count < f->breakUp)
		{
			rcv->tqDefault = getTQ(rcv->mac);
		}
		else
		{
			continue;
		}

		// evaluate the best quality default route
		if(rcv->tqDefault != 0)
		{
			if(i == 0)
			{
				tqTmp = rcv->tqDefault;
				suitableDefaultId = rcv->rt_table_id;
			}
			if (tqTmp < rcv->tqDefault)
			{
				tqTmp = rcv->tqDefault;
				suitableDefaultId = rcv->rt_table_id;
			}
			i++;
		}
	}

	// if the previous default rule is not suitable anymore, then delete the rule for it
	if(previousDefaultId != suitableDefaultId && previousDefaultId != 0)
	{
		HASH_FIND(hh1, nodes_by_rt_table_id, &previousDefaultId, sizeof(previousDefaultId), rcv);
		if(rcv != NULL)
		{
			sprintf(ip_cmd, "ip rule del from all priority %d table %d", DEFAULT_PRIORITY, rcv->rt_table_id);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* delrule = popen(ip_cmd, "w");
			errCatchFunc(delrule, 7);
			pclose(delrule);
			rcv->isDefault = 0;
		}
	}

	// find and add rule for suitable default route if it is not added yet
	// if the 'suitableDefaultId' is 0 then the search will not give anything, so there is no default route
	HASH_FIND(hh1, nodes_by_rt_table_id, &suitableDefaultId, sizeof(suitableDefaultId), rcv);
	if(rcv != NULL)
	{
		if(rcv->isDefault == 0)
		{
			sprintf(ip_cmd, "ip rule add from all priority %d table %d", DEFAULT_PRIORITY, rcv->rt_table_id);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* addrule = popen(ip_cmd, "w");
			errCatchFunc(addrule, 8);
			pclose(addrule);
			rcv->isDefault = 1;
		}
	}
}

void deleteRoute(pull *rcv, char *p_route, char ip_cmd[])
{
	sprintf(ip_cmd,"/sbin/ip route del %s via %s table %d", p_route, rcv->ipv4, rcv->rt_table_id);
	syslog(LOG_INFO, "%s", ip_cmd);
	FILE *del0 = popen(ip_cmd, "w");
	errCatchFunc(del0, 9);
	pclose(del0);

	if(strcmp(p_route, DEFAULT_LABEL) != 0)
	{
		sprintf(ip_cmd, "/sbin/ip rule del from all to %s priority %d table %d", p_route, REGULAR_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE *del2 = popen(ip_cmd, "w");
		errCatchFunc(del2, 10);
		pclose(del2);
	}
}

void addRoute(pull *rcv, char *p_route, char ip_cmd[])
{
	sprintf(ip_cmd, "/sbin/ip route replace %s via %s table %d", p_route, rcv->ipv4, rcv->rt_table_id);
	syslog(LOG_INFO, "%s", ip_cmd);
	FILE *add0 = popen(ip_cmd, "w");
	errCatchFunc(add0, 11);
	pclose(add0);

	if(strcmp(p_route, DEFAULT_LABEL) != 0)
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
				if(strstr(p_route, DEFAULT_LABEL) && rcv->isDefault == 1)
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
			else if(strcmp(p_lineBuf, DEFAULT_LABEL) == 0)
			{
				defflag++;
				if(defflag > 1)
				{
					return -1;
				}
			}
			// if this is not an ip address
			else if(strcmp(p_lineBuf, DEFAULT_LABEL) != 0)
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

int getTQ(char *macAddr)
{
	char batctl_cmd[100] = {0x0};
	char batctl_line[100] = {0x0};
	char originatorStr[100] = {0x0};
	char *ptr;
	char TQstr[100] = {0x0};
	int TQint = 0;

	// converting bat mac address to originator mac address
	sprintf(batctl_cmd, "/usr/sbin/batctl t %s", macAddr);
	FILE* batctl_pipe = popen(batctl_cmd, "r");
	errCatchFunc(batctl_pipe, 16);
	if(fgets(batctl_line, sizeof(batctl_line), batctl_pipe))
	{
		// adding '*' to the gotten originator mac address
		sprintf(originatorStr, "* %s", strtok(batctl_line, "\n"));
		// show BATMAN table 
		FILE* batctl_pipe2 = popen("/usr/sbin/batctl o -H", "r");
		errCatchFunc(batctl_pipe, 17);
		while(fgets(batctl_line, sizeof(batctl_line), batctl_pipe2) != NULL)
		{
			// find originator mac in BATMAN table
			if(strstr(batctl_line, originatorStr) != NULL)
			{
				// cutting the line to tokens until TQ field
				ptr = strtok(batctl_line, " ");
				for(int i = 0; i < 3; i++)
				{
					ptr = strtok(NULL, " ");
				}
				// cutting out the brackets
				snprintf(TQstr, strlen(ptr)-1, "%s", ptr+1);
				// convert the string to the integer type
				TQint = strtol(TQstr, &ptr, 10);
				break;
			}
		}
		pclose(batctl_pipe2);
	}
	pclose(batctl_pipe);
	return TQint;
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

