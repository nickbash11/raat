#include "raat.h"

#define DEFAULT_PRIORITY 33333
#define REGULAR_PRIORITY 30000

static pull *nodes_by_rt_table_id = NULL, *nodes_by_mac = NULL;

void flushRulesRoutes(void)
{
	char line[1000] = {0x0};
	char defaultPriorityBuf[10] = {0x0};
	char regularPriorityBuf[10] = {0x0};
	char lineBuf[1000] = {0x0};
	char ip_cmd[100] = {0x0};
	char *p_lineBuf;

	// convert integer to string
	sprintf(defaultPriorityBuf, "%d", DEFAULT_PRIORITY);
	sprintf(regularPriorityBuf, "%d", REGULAR_PRIORITY);

	// open pipe for reading
	FILE* rules_read0 = popen("/sbin/ip rule", "r");
	if(rules_read0 == NULL)                        
	{
		syslog(LOG_ERR, "Pull point 0");
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(1);
	}

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
			if(flush0 == NULL)
			{
				syslog(LOG_ERR, "Pull point 1");
				syslog(LOG_ERR, "Value of errno: %d", errno);
				syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
				exit(1);
			}
			pclose(flush0);

			sprintf(ip_cmd, "/sbin/ip rule del %s", lineBuf);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* flush1 = popen(ip_cmd, "w");
			if(flush1 == NULL)
			{
				syslog(LOG_ERR, "Pull point 2");
				syslog(LOG_ERR, "Value of errno: %d", errno);
				syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
				exit(1);
			}
			pclose(flush1);
		}
	}
	//close pipe
	pclose(rules_read0);

	// open pipe for reading
	FILE* rules_read1 = popen("/sbin/ip rule", "r");
	if(rules_read1 == NULL)
	{
		syslog(LOG_ERR, "Pull point 3");
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(1);
	}

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
			if(flush0 == NULL)
			{
				syslog(LOG_ERR, "Pull point 4");
				syslog(LOG_ERR, "Value of errno: %d", errno);
				syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
				exit(1);
			}
			pclose(flush0);

			sprintf(ip_cmd, "/sbin/ip rule del %s", lineBuf);
			syslog(LOG_INFO, "%s", ip_cmd);
			FILE* flush1 = popen(ip_cmd, "w");
			if(flush1 == NULL)
			{
				syslog(LOG_ERR, "Pull point 5");
				syslog(LOG_ERR, "Value of errno: %d", errno);
				syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
				exit(1);
			}
			pclose(flush1);
		}
	}
	// close pipe
	pclose(rules_read1);
}

void getAndSetStruct(push *snd, pull *rcv, flags *f)
{
	int num;
	char macBuf[18] = {0x0};
	char payloadBuf[1000] = {0x0};
	char *p_payloadGap;
	char payloadToHash[1000] = {0x0};	
	char line[1000] = {0x0};
	char alfred_cmd[20] = {0x0};

	sprintf(alfred_cmd, "alfred -r %d", f->dataType);
	FILE* alfred_pipe = popen(alfred_cmd, "r");
	if(alfred_pipe == NULL)
	{
		syslog(LOG_ERR, "Pull point 6");
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(1);
	}

	while(fgets(line, sizeof(line), alfred_pipe) != NULL)
	{
		// skip its own record
		if(strstr(line, snd->batmanAddr))
		{
			continue;
		}

		// skip lines which less than 50 symbols
		if(strlen(line) < 50)
		{
			continue;
		}

		// copy string with mac to a buffer
		snprintf(macBuf, 18, "%s", line+3);

		// copy string with payload info to a buffer
		snprintf(payloadBuf, strlen(line+24)-4, "%s", line+24);

		// add a new one
		HASH_FIND(hh2, nodes_by_mac, macBuf, strlen(macBuf), rcv);
		if(rcv == NULL)
		{
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

			// split payload string, the first piece (is unix timestamp)
			p_payloadGap = strtok(payloadBuf, "*");

			// split payload string, other pieces (routes)
			int r = -2;
			while(p_payloadGap != NULL)
			{
				if(r == -2)
				{
					// first string with unix timestamp
					rcv->node_timestamp = atoi(p_payloadGap);
				}
				else if(r == -1)
				{
					// copy ipv4 address
					strcpy(rcv->ipv4, p_payloadGap);
				}
				else
				{
					// add routes to their struct place
					rcv->p_route_update[r] = malloc(2+strlen(p_payloadGap));
					strcpy(rcv->p_route_update[r], p_payloadGap);

					// put routes to hashable var
					strcat(payloadToHash, p_payloadGap);
				}
				p_payloadGap = strtok(NULL, "*");
				r++;
			}
			// set the hash for routes
			rcv->route_hash = sdbm(payloadToHash);
		} else {
		// the item exists
			// split payload string, the first piece (is unix timestamp)
			p_payloadGap = strtok(payloadBuf, "*");

			// split payload string, other pieces (routes)
			int r = -2;
			while(p_payloadGap != NULL)
			{
				if(r == -2)
				{
					// first string with unix timestamp
					rcv->node_timestamp = atoi(p_payloadGap);

					// if the timestamp status is not updated - no point to update routes, just skip
					if(rcv->node_timestamp == rcv->node_timestamp_tmp)
					{
						goto skip;
					}

					// clear routes
					memset(rcv->p_route_update, 0, 100*sizeof(*rcv->p_route_update));
				}
				else if(r == -1)
				{
					// ipv4 address has already gotten, do nothing
				}
				else
				{
					// add routes to their struct place
					rcv->p_route_update[r] = malloc(2+strlen(p_payloadGap));
					strcpy(rcv->p_route_update[r], p_payloadGap);

					// put routes to hashable var
					strcat(payloadToHash, p_payloadGap);
				}
				p_payloadGap = strtok(NULL, "*");
				r++;
			}
			// set the has for routes
			rcv->route_hash = sdbm(payloadToHash);
		}
		skip:;

		// hashable variable, reset for every new node
		payloadToHash[0] = '\0';
	}
	pclose(alfred_pipe);
}

void checkStatus(flags *f, pull *rcv)
{
	char ip_cmd[100] = {0x0};
	int flag, ru, rc, r;
	// get each node
	for(rcv=nodes_by_mac; rcv != NULL; rcv=rcv->hh2.next)
	{
		// if timestamps are not equal
		if(rcv->node_timestamp != rcv->node_timestamp_tmp)
		{
			// set timestamp to current and breakup counter to zero
			rcv->node_timestamp_tmp = rcv->node_timestamp;
			rcv->breakup_count = 0;

			// check if routes hash did not change - skip
			if(rcv->route_hash == rcv->route_hash_tmp)
			{
				// check if the node has back after breakup
				if(rcv->p_route_current[0] != NULL)
				{
					continue;
				}
			}
			else
			{
				// set new hash number to old
				rcv->route_hash_tmp = rcv->route_hash;
			}

			// if there are "none" in the alfred table
			if(strcmp(rcv->p_route_update[0], "none") == 0)
			{

				// clear routes and s->p_route_current[r]
				r = 0;
				while(rcv->p_route_current[r] != NULL)
				{
					deleteRoute(rcv, r, ip_cmd);
					r++;
				}
				// clear memory
				memset(rcv->p_route_current, 0, 100*sizeof(*rcv->p_route_current));
				// go to the next iteration
				continue;
			}
			else
			{
				/* here below we check for what rules and routes need to delete
				* first we call the entry from "p_route_current" and compare it between each entry from "p_route_update" one by one
				* p_route_current[0] --> p_route_update[0]
				*                    \_> p_route_update[1]
				*                    \_> p_route_update[2]
				*/
				rc = 0;
				while(rcv->p_route_current[rc] != NULL)
				{
					ru = 0;
					flag = 0;
					while(rcv->p_route_update[ru] != NULL)
					{
						if(strcmp(rcv->p_route_update[ru], rcv->p_route_current[rc]) == 0)
						{
							flag++;
							break;
						}
						ru++;
					}
					// if the counter "upd" is equal zero, the route is not presented in update array, need to delete from current
					if(flag == 0)
					{
						deleteRoute(rcv, rc, ip_cmd);
					}
					rc++;
				}

				/* here below we check for what rules and routes need to add
				* first we call the entry from "p_route_update" and compare it between each entry from "p_route_current" one by one
				* p_route_update[0] --> p_route_current[0]
				*                   \_> p_route_current[1]
				*                   \_> p_route_current[2]
				*/
				ru = 0;
				while(rcv->p_route_update[ru] != NULL)
				{
					rc = 0;
					flag = 0;
					while(rcv->p_route_current[rc] != NULL)
					{
						if(strcmp(rcv->p_route_update[ru], rcv->p_route_current[rc]) == 0)
						{
							flag++;
							break;
						}
						rc++;
					}
					// if the counter "curr" is equal zero, the route is not presented in current array, need to add to current
					if(flag == 0)
					{
						addRoute(rcv, ru, ip_cmd);
					}
					ru++;
				}

				// clear p_route_current
				memset(rcv->p_route_current, 0, 100*sizeof(*rcv->p_route_current));

				// rewrite p_route_current with p_route_update
				r = 0;
				while(rcv->p_route_update[r] != NULL)
				{
					rcv->p_route_current[r] = malloc(2+strlen(rcv->p_route_update[r]));
					strcpy(rcv->p_route_current[r], rcv->p_route_update[r]);
//					printf("current: %s\n", rcv->p_route_current[r]);
					r++;
				}

			}
		}
		else
		{
			// here we count how many times the node is not updated
			rcv->breakup_count++;
			if(rcv->breakup_count > f->breakUp)
			{
				syslog(LOG_INFO, "%s is dead %d times ago", rcv->mac, rcv->breakup_count);
				// the node is dead, clear rules from this point
				r = 0;
				while(rcv->p_route_current[r] != NULL)
				{
					deleteRoute(rcv, r, ip_cmd);
					r++;
				}

				if(rcv->p_route_current[0] != NULL)
				{
					// clear p_route_current
					memset(rcv->p_route_current, 0, 100*sizeof(*rcv->p_route_current));
				}
			}
		}
	}
}

void deleteRoute(pull *rcv, int r, char ip_cmd[])
{
	sprintf(ip_cmd,"/sbin/ip route del %s via %s table %d", rcv->p_route_current[r], rcv->ipv4, rcv->rt_table_id);
	syslog(LOG_INFO, "%s", ip_cmd);
	FILE *del0 = popen(ip_cmd, "w");
	if(del0 == NULL)
	{
		syslog(LOG_ERR, "Pull point 7");
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(1);
	}
	pclose(del0);

	if(strcmp(rcv->p_route_current[r], "default") == 0)
	{
		sprintf(ip_cmd, "/sbin/ip rule del from all priority %d table %d 2>/dev/null", DEFAULT_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE *del1 = popen(ip_cmd, "w");
		if(del1 == NULL)
		{
			syslog(LOG_ERR, "Pull point 8");
			syslog(LOG_ERR, "Value of errno: %d", errno);
			syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
			exit(1);
		}
		pclose(del1);
	}
	else
	{
		sprintf(ip_cmd, "/sbin/ip rule del from all to %s priority %d table %d 2>/dev/null", rcv->p_route_current[r], REGULAR_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE *del2 = popen(ip_cmd, "w");
		if(del2 == NULL)
		{
			syslog(LOG_ERR, "Pull point 9");
			syslog(LOG_ERR, "Value of errno: %d", errno);
			syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
			exit(1);
		}
		pclose(del2);
	}
}

void addRoute(pull *rcv, int r, char ip_cmd[])
{
	sprintf(ip_cmd, "/sbin/ip route replace %s via %s table %d", rcv->p_route_update[r], rcv->ipv4, rcv->rt_table_id);
	syslog(LOG_INFO, "%s", ip_cmd);
	FILE *add0 = popen(ip_cmd, "w");
	if(add0 == NULL)
	{
		syslog(LOG_ERR, "Pull point 10");
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(1);
	}
	pclose(add0);

	if(strcmp(rcv->p_route_update[r], "default") == 0)
	{
		sprintf(ip_cmd, "/sbin/ip rule add from all priority %d table %d 2>/dev/null", DEFAULT_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE* add1 = popen(ip_cmd, "w");
		if(add1 == NULL)
		{
			syslog(LOG_ERR, "Pull point 11");
			syslog(LOG_ERR, "Value of errno: %d", errno);
			syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
			exit(1);
		}
		pclose(add1);
	}
	else
	{
		sprintf(ip_cmd, "/sbin/ip rule add from all to %s priority %d table %d 2>/dev/null", rcv->p_route_update[r], REGULAR_PRIORITY, rcv->rt_table_id);
		syslog(LOG_INFO, "%s", ip_cmd);
		FILE* add2 = popen(ip_cmd, "w");
		if(add2 == NULL)
		{
			syslog(LOG_ERR, "Pull point 12");
			syslog(LOG_ERR, "Value of errno: %d", errno);
			syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
			exit(1);
		}
		pclose(add2);
	}
}

void removeExpired(pull *rcv, flags *f)
{
	char line[1000] = {0x0};
	char ip_cmd[100] = {0x0};
	int flag, r;
	char alfred_cmd[20] = {0x0};

	sprintf(alfred_cmd, "alfred -r %d", f->dataType);

	for(rcv=nodes_by_mac; rcv != NULL; rcv=rcv->hh2.next)
	{
		FILE* alfred_pipe = popen(alfred_cmd, "r");
		if(alfred_pipe == NULL)
		{
			syslog(LOG_ERR, "Pull point 13");
			syslog(LOG_ERR, "Value of errno: %d", errno);
			syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
			exit(1);
		}

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
			if(flush0 == NULL)
			{
				syslog(LOG_ERR, "Pull point 14");
				syslog(LOG_ERR, "Value of errno: %d", errno);
				syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
				exit(1);
			}
			pclose(flush0);

			r = 0;
			while(rcv->p_route_current[r])
			{
				if(strstr(rcv->p_route_current[r], "default"))
				{
					sprintf(ip_cmd, "/sbin/ip rule del from all priority %d lookup %d", DEFAULT_PRIORITY, rcv->rt_table_id);
				}
				else
				{
					sprintf(ip_cmd, "/sbin/ip rule del from all to %s priority %d lookup %d", rcv->p_route_current[r], REGULAR_PRIORITY, rcv->rt_table_id);
				}
				syslog(LOG_INFO, "%s", ip_cmd);
				FILE* flush1 = popen(ip_cmd, "w");
				if(flush1 == NULL)
				{
					syslog(LOG_ERR, "Pull point 15");
					syslog(LOG_ERR, "Value of errno: %d", errno);
					syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
					exit(1);
				}
				pclose(flush1);
				r++;
			}
			HASH_DELETE(hh2, nodes_by_mac, rcv);
			HASH_DELETE(hh1, nodes_by_rt_table_id, rcv);
			free(rcv);
		}
		pclose(alfred_pipe);
	}
}

/* http://www.cse.yorku.ca/~oz/hash.html */
unsigned long sdbm(char *str)
{
	unsigned long hash = 0;
	int c;

	while ((c = *str++))
		hash = c + (hash << 6) + (hash << 16) - hash;

	return hash;
}

