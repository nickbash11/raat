#include "raat.h"

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
		exit(1);
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
		syslog(LOG_ERR, "%s does not exist or has no ipv4 address\n", snd->batmanIf);
		exit(1);
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
			exit(1);
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
			}
		}
		fclose(fp);
	}
}

void getLocalRoutes(push *snd)
{
	if(snd->lanPublish == 1)
	{
		int r;
		char line[1000];

		FILE* fp = popen("/sbin/ip route", "r");
		if( fp == NULL )
		{
			syslog(LOG_ERR, "Push point 2");
			syslog(LOG_ERR, "Value of errno: %d", errno);
			syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
			exit(1);
		}

		// clear garbage before using
		memset(snd->p_localRoutes, 0, sizeof(snd->p_localRoutes));

		r = 0;
		while(fgets(line, sizeof(line), fp) != NULL)
		{
			if(strstr(line, "br-") != NULL) {
				snd->p_localRoutes[r] = (char*)malloc(2+strlen(strtok(line, " ")));
				memset(snd->p_localRoutes[r], 0, 2+strlen(strtok(line, " ")));
				strcpy(snd->p_localRoutes[r], strtok(line, " "));
				r++;
			} 
		}
		pclose(fp);
	}
}

void pushData(push *snd, flags *f)
{
	// open for Alfred's pipe
	int r;
	char alfred_cmd[50] = {0x0};  

	sprintf(alfred_cmd, "/usr/sbin/alfred -s %d", f->dataType);

	FILE* alfred_pipe = popen(alfred_cmd, "w");
	if(alfred_pipe == NULL)
	{
		syslog(LOG_ERR, "Push point 3");
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(1);
	}

	// put unix timestamp first
	int timestamp = (int)time(NULL);
	fprintf(alfred_pipe, "%d*", timestamp);

	// put ipv4 address second
	fprintf(alfred_pipe, "%s*", snd->batmanAddr);

	if(snd->wanRouteExists == 0 && snd->p_localRoutes[0] == NULL) {
		fputs("none*", alfred_pipe);
	}

	if(snd->wanRouteExists == 1) {
		fputs("default*", alfred_pipe);
	}

	r = 0;
	while(snd->p_localRoutes[r] != NULL) {
		fprintf(alfred_pipe, "%s*", snd->p_localRoutes[r]);
		free(snd->p_localRoutes[r]);
		r++;
	}

	// close alfred pipe
	pclose(alfred_pipe);
}
