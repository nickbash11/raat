#include "raat.h"

#define MAX_ROUTES 10
#define FIND_LAN_STR "br-"

void checkBatIf(push *snd)
{
	int i = 0;
	char line[1000] = {0x0};

	FILE *fp = fopen("/proc/net/route", "r");
	if( fp == NULL )
	{
		syslog(LOG_ERR, "Push point 0");
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(-1);
	}

	while(fgets(line, sizeof(line), fp) != NULL)
	{
		// there is the tab
		strtok(line, "	");
		if(strcmp(line, snd->batmanIf) == 0)
		{
			i++;
			break;
		}
	}
	fclose(fp);

	if(i == 0)
	{
		fprintf(stderr, "%s does not exist or has no ipv4 address\n", snd->batmanIf);
		exit(-1);
	}
}

// https://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php 
void getBatIpAddr(push *snd)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "bat0" */
	strncpy(ifr.ifr_name, snd->batmanIf, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	strcpy(snd->batmanAddr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void wanRouteExists(push *snd)
{
	if(snd->wanPublish == 1)
	{
		char line[1000] = {0x0};
		char lineBuf[1000] = {0x0};
		char *p_lineBuf;

		FILE *fp = fopen("/proc/net/route", "r");
		if( fp == NULL )
		{
			syslog(LOG_ERR, "Push point 1");
			syslog(LOG_ERR, "Value of errno: %d", errno);
			syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
			exit(-1);
		}

		while(fgets(line, sizeof(line), fp))
		{
			// there is the tab
			p_lineBuf = strtok(line, "	");
			sprintf(lineBuf, "%s", p_lineBuf);

			// there is the tab
			p_lineBuf = strtok(NULL, "	");
			if(strcmp(p_lineBuf, "00000000") == 0 && strcmp(lineBuf, snd->batmanIf) != 0)
			{
				snd->wanRouteExists = 1;
				break;
			}
			else
			{
				snd->wanRouteExists = 0;
			}
		}
		fclose(fp);
	}
}

void getLocalRoutes(push *snd)
{
	if(snd->lanPublish == 1)
	{
		char line[1000] = {0x0};
		char *p_lineBuf;

		// set counter to zero
		snd->localRoutesCount = 0;
		// reset localRoutes to NULL
		memset(snd->localRoutes, 0, sizeof(snd->localRoutes));

		// open the pipe for ip
		FILE* fp = popen("ip route", "r");
		if( fp == NULL )
		{
			syslog(LOG_ERR, "Push point 2");
			syslog(LOG_ERR, "Value of errno: %d", errno);
			syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
			exit(-1);
		}

		// if the line is not NULL then
		while(fgets(line, sizeof(line), fp) != NULL)
		{
			// find FIND_LAN_STR and assign it to snd->localRoutes
			if(strstr(line, FIND_LAN_STR) != NULL) {
				p_lineBuf = strtok(line, " ");
				strcat(snd->localRoutes, p_lineBuf);
				strcat(snd->localRoutes, "*");
				snd->localRoutesCount++;

				// the condition for the max quantity of local routes to push
				if(snd->localRoutesCount == MAX_ROUTES)
				{
					break;
				}
			}
		}
		pclose(fp);
	}
}

void pushData(push *snd, flags *f)
{
	// open for Alfred's pipe
	char alfred_cmd[50] = {0x0};  

	// put the number of data type to the alfred pipe
	sprintf(alfred_cmd, "/usr/sbin/alfred -s %d", f->dataType);

	// open the alfred pipe to push
	FILE* alfred_pipe = popen(alfred_cmd, "w");
	if(alfred_pipe == NULL)
	{
		syslog(LOG_ERR, "Push point 3");
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(-1);
	}

	// put unix timestamp first
	int timestamp = (int)time(NULL);
	fprintf(alfred_pipe, "%d*", timestamp);

	// put ipv4 address second
	fprintf(alfred_pipe, "%s*", snd->batmanAddr);

	// put "none" if there are neither wan nor routes
	if(snd->wanRouteExists == 0 && snd->localRoutes[0] == 0)
	{
		fputs("none*", alfred_pipe);
	}

	// put "default" if there is the wan
	if(snd->wanRouteExists == 1)
	{
		fputs("default*", alfred_pipe);
	}

	// put the other routes if they exist
	if(snd->localRoutes[0] != 0)
	{
		fprintf(alfred_pipe, "%s", snd->localRoutes);
	}

	// close alfred pipe
	pclose(alfred_pipe);
}
