#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>

#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "uthash.h"

extern int errno;

typedef struct {
	int iflag;
	int hflag;
	int wflag;
	int lflag;
	int sflag;
	int bflag;
	int tflag;
	int Dflag;
	int breakUp;
	int dataType;
	int sleepTime;
} flags;

typedef struct {
	int rt_table_id;
	char mac[20]; 
	char ipv4[20];
	char routes[500];
	int breakup_count;
	int node_timestamp;
	int node_timestamp_previous;
	UT_hash_handle hh1, hh2; 
} pull;

typedef struct {
	char batmanIf[15];
	char batmanAddr[32];
	int wanRouteExists;
	int wanPublish;
	int lanPublish;
	char localRoutes[1000];
	int localRoutesCount;
} push;

//push functions
void checkBatIf(push *snd);
void getBatIpAddr(push *snd);
void wanRouteExists(push *snd);
void getLocalRoutes(push *snd);
void pushData(push *snd, flags *f);

//pull functions
void flushRulesRoutes(void);
void getRoutes(pull *rcv, flags *f);
void deleteRoute(pull *rcv, char *p_route, char ip_cmd[]);
void addRoute(pull *rcv, char *p_route, char ip_cmd[]);
void removeExpired(pull *rcv, flags *f);
int payloadValidator(char line[]);

