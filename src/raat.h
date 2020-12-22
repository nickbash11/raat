#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>

#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#include "uthash.h"

extern int errno;

// the structure which keeps the command line flags
typedef struct {
	int iflag;
	int hflag;
	int wflag;
	int lflag;
	int sflag;
	int mflag;
	int tflag;
	int vflag;
	int Iflag;
	int miss;
	int dataType;
	int sleepTime;
} flags;

// the structure which keeps all information about every node in cloud
typedef struct {
	int rt_table_id;
	char mac[20]; 
	char macOrig[20];
	char ipv4[20];
	char routes[500];
	int tqDefault;
	int isDefault;
	int miss_count;
	long node_timestamp;
	long node_timestamp_previous;
	UT_hash_handle hh1, hh2; 
} pull;

// the stucture which keeps the information about the local routes to push and other local etc
typedef struct {
	char batmanIf[15];
	char batmanAddr[32];
	int wanRouteExists;
	int wanPublish;
	int lanPublish;
	char localRoutes[512];
} push;

extern pull *nodes_by_rt_table_id, *nodes_by_mac;

// common functions
void readSharedMemory(void);
void writeSharedMemory(flags *f, pull *rcv, push *snd);
void clearSharedMemory(void);
void errCatchFunc(FILE *pipe, char *filename, int point);
void SIGQUIT_handler(int sig);
char * getIfMac(char *ifName);

// main functions
void checkArgs(flags *f, push *snd);
void daemonize(void);
int setPid(void);
pid_t proc_find(const char* name);

// push functions
void checkBatIf(push *snd);
void getBatIpAddr(push *snd);
void wanRouteExists(push *snd);
void getLocalRoutes(push *snd);
void pushData(push *snd, flags *f);

// pull functions
void flushRulesRoutes(void);
void getSetRoutes(push *snd, pull *rcv, flags *f);
void removeExpired(pull *rcv, flags *f);
void setDefaultRoute(pull *rcv, flags *f);
void addDeleteRoute(pull *rcv, char *p_route, char *p_action);
int payloadValidator(char line[]);
int getTQ(char *macAddrOrig);
void setOriginatorMac(pull *rcv, char *macAddr);
