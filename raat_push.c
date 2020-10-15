#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MESHNETWORK "mesh"
#define WANNETWORK "wan"

int getBatIf(char *p_batIf[], char *p_meshNetwork);
int getBatIpAddr(char *p_batAddr[], char *p_meshNetwork);
int wanIfaceExists(int *p_wanIfExists, char *wanNetwork);
int wanRouteExists(int *p_wanRouteExists, char *p_batIf);
int getLocalRoutes(char *p_localRoutes[]);

int main ()
{

int k = 0;

while(1) {
	k++;
	printf("------iteration %d------\n", k);

	// Get BATMAN interface name
	char *p_batIf[100];
	getBatIf(p_batIf, MESHNETWORK);

	// Check if BATMAN interface is not available
	if(p_batIf[0] == NULL) {
		printf("exit\n");
		return 0;
	}

	// Get BATMAN ipv4 address
	char *p_batAddr[100];
	getBatIpAddr(p_batAddr, MESHNETWORK);

	// Get if WAN interface exists
	int wanIfExists = 0;
	int *p_wanIfExists = &wanIfExists;
	wanIfaceExists(p_wanIfExists, WANNETWORK);

	// Get if Wan route exists
	int wan1RouteExists = 0;
	int *p_wanRouteExists = &wan1RouteExists;
	wanRouteExists(p_wanRouteExists, p_batIf[0]);

	// Get local LAN routes
	char *p_localRoutes[100];
	getLocalRoutes(p_localRoutes);

	// Opening for Alfred's pipe
	char push[1000] = "none";
	FILE* alfred = popen("alfred -s 100", "w+");

	if((wan1RouteExists == 0 || wanIfExists == 0) && p_localRoutes[0] == NULL) {
		printf("%s\n", push);
		fputs(push, alfred);
		fclose(alfred);
		return 0;
	} 

	if(wan1RouteExists == 1 && wanIfExists == 1) {
		sprintf(push, "default via %s\n", p_batAddr[0]);
		printf("%s", push);
		fputs(push, alfred);
	}

	int i = 0;
	while(p_localRoutes[i] != NULL) {
		sprintf(push, "%s via %s\n", p_localRoutes[i], p_batAddr[0]);
		printf("%s", push);
		fputs(push, alfred);
		i++;
	}

	fclose(alfred);

	printf("-----------------------\n");
	sleep(1);
} 


	return 0;
}

int getBatIf(char *p_batIf[], char *p_meshNetwork)
{
	char cmd1[100] = {0x0};
	char cmd2[100] = {0x0};

	sprintf(cmd1,"uci -q get network.%s.ifname", p_meshNetwork);
	FILE* fp1 = popen(cmd1, "r");
	char line1[100] = {0x0};

	memset(p_batIf, 0, 10*sizeof(*p_batIf));

	if(fgets(line1, sizeof(line1), fp1) != NULL) {

		sprintf(cmd2,"ip link show dev %s", line1);
		FILE* fp2 = popen(cmd2, "r");
		char line2[2000] = {0x0};

		if(fgets(line2, sizeof(line2), fp2) == NULL) {
			pclose(fp1);
			pclose(fp2);
			return 1;
		} else {
			p_batIf[0] = (char*)malloc(2+strlen(strtok(line1,"\n")));
			strcpy(p_batIf[0], strtok(line1, "\n"));
		}
		pclose(fp2);
	}
		
	pclose(fp1);
	return 0;
}

int getBatIpAddr(char *p_batAddr[], char *p_meshNetwork)
{
	char cmd[100] = {0x0};
	sprintf(cmd,"uci -q get network.%s.ipaddr", p_meshNetwork);
	FILE* fp = popen(cmd, "r");
	char line[64] = {0x0};

	memset(p_batAddr, 0, 10*sizeof(*p_batAddr));

	if(fgets(line, sizeof(line), fp) != NULL)
		p_batAddr[0] = (char*)malloc(2+strlen(strtok(line,"\n")));
		strcpy(p_batAddr[0], strtok(line, "\n"));

	pclose(fp);
	return 0;
}


int wanIfaceExists(int *p_wanIfExists, char *wanNetwork)
{
	char cmd[100] = {0x0};
	sprintf(cmd,"uci -q get network.%s.ifname", wanNetwork);
	FILE* fp = popen(cmd,"r");
	char line[64] = {0x0};

	if(fgets(line, sizeof(line), fp) != NULL)
		*p_wanIfExists = 1;

	pclose(fp);
	return 0;
}

int wanRouteExists(int *p_wanRouteExists, char *p_batIf)
{
	FILE* fp = popen("ip route show table main", "r");
	char line[1000] = {0x0};

	while(fgets(line, sizeof(line), fp) != NULL)
	{
		if(strstr(line, "default via") != NULL && strstr(line, p_batIf) == NULL) {
			*p_wanRouteExists = 1;
		}
	}
	
	pclose(fp);
	return 0;
}

int getLocalRoutes(char *p_localRoutes[])
{
	int i = 0;
	FILE* fp = popen("ip route", "r");
	char line[1000];

	memset(p_localRoutes, 0, 10*sizeof(*p_localRoutes));

	while(fgets(line, sizeof(line), fp) != NULL)
	{
		if(strstr(line, "br-") != NULL) {
			p_localRoutes[i] = (char*)malloc(2+strlen(strtok(line, " ")));
			strcpy(p_localRoutes[i], strtok(line, " "));
			i++;
		} 
	}

	pclose(fp);
	return 0;
}
