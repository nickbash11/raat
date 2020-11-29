#include "raat.h"

#define SHMSIZE 65536
#define SHMKEY 7893245

void readSharedMemory(void)
{
	int shmid;
	char *string;

	// set the id for payload segment
	if ((shmid = shmget(SHMKEY, SHMSIZE, 0)) == -1)
	{
		syslog(LOG_ERR, "shmget read");
		perror("shmget");
		exit(-1);
	}

	// assign the segment to the pointer
	string = shmat(shmid, (void *)0, 0);
	if (string == (char *)(-1))
	{
		syslog(LOG_ERR, "shmat read");
		perror("shmat");
		exit(-1);
	}

	printf("%s\n", string);

	// detach the segment
	shmdt((void *) string);
}

void writeSharedMemory(pull *rcv)
{
	int shmid;
	char *string;
	char buf[1024];

	if ((shmid = shmget(SHMKEY, SHMSIZE, IPC_CREAT | 0644)) == -1)
	{
		syslog(LOG_ERR, "shmget write");
		perror("shmget");
		exit(-1);
	}

	// assign the segment to the pointer
	string = shmat(shmid, (void *)0, 0);
	if (string == (char *)(-1))
	{
		syslog(LOG_ERR, "shmat write");
		perror("shmat");
		exit(-1);
	}

	time_t now = time (0);
	strftime (buf, 100, "last update: %Y-%m-%d %H:%M:%S\n\n", localtime (&now));

	// copy the content of buffer to the segment
	strcpy(string, "\0");
	// add last time
	strcat(string, buf);
	// add columns
	strcat(string, "mac			originator		timestamp	breakups	ipv4		routes\n");

	for(rcv=nodes_by_mac; rcv != NULL; rcv=rcv->hh2.next)
	{
		if(rcv->isDefault == 0)
		{
			sprintf(buf, "%s	%s	%d	%d		%s	%s\n", rcv->mac, rcv->macOrig, rcv->node_timestamp, rcv->breakup_count, rcv->ipv4, rcv->routes);
			strcat(string, buf);
		}
	}

	strcat(string, "\n");

	for(rcv=nodes_by_mac; rcv != NULL; rcv=rcv->hh2.next)
	{
		if(rcv->isDefault == 1)
		{
			strcat(string, "default route:\n");
			sprintf(buf, "%s	%s	%d	%d		%s	%s\n", rcv->mac, rcv->macOrig, rcv->node_timestamp, rcv->breakup_count, rcv->ipv4, rcv->routes);
			strcat(string, buf);
		}
	}

	// detach the segment
	shmdt((void *) string);
} 

void clearSharedMemory(void)
{
	int shmid;

	// set the id for payload segment
	if ((shmid = shmget(SHMKEY, SHMSIZE, 0)) == -1)
	{
		syslog(LOG_ERR, "shmget read");
		perror("shmget");
		exit(-1);
	}

	// destroy the segment
	shmctl(shmid, IPC_RMID, NULL);
}

// catch for errors
void errCatchFunc(FILE *pipe, char *filename, int point)
{
	if(pipe == NULL)
	{
		syslog(LOG_ERR, "Point %d in file %s", point, filename);
		syslog(LOG_ERR, "Value of errno: %d", errno);
		syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
		exit(-1);
	}
}

void SIGQUIT_handler(int sig)
{                             
	signal(sig, SIG_IGN);
	syslog(LOG_INFO, "Goodbye...\n");

	clearSharedMemory();
	closelog();

	exit(3);
}            

