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

// the structure which keeps the command line flags
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

// the structure which keeps all information about every node in cloud
typedef struct {
	int rt_table_id;
	char mac[20]; 
	char ipv4[20];
	char routes[500];
	int tqDefault;
	int isDefault;
	int breakup_count;
	int node_timestamp;
	int node_timestamp_previous;
	UT_hash_handle hh1, hh2; 
} pull;

// the stucture which keeps the information about the local routes to push and other local etc
typedef struct {
	char batmanIf[15];
	char batmanAddr[32];
	int wanRouteExists;
	int wanPublish;
	int lanPublish;
	char localRoutes[1000];
	int localRoutesCount;
} push;

// common push functions
void checkBatIf(push *snd);
void getBatIpAddr(push *snd);
void wanRouteExists(push *snd);
void getLocalRoutes(push *snd);
void pushData(push *snd, flags *f);

// common pull functions
void flushRulesRoutes(void);
void getSetRoutes(push *snd, pull *rcv, flags *f);
void removeExpired(pull *rcv, flags *f);

