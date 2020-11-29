#include "raat.h"

#define SIZE 65536
#define KEY 7893245

void setTheInfo(pull *rcv, char *action)
{
	int shmid;
	char *string;
	char buf[1024];

	if(strcmp(action, "read") == 0)
	{
		// set the id for payload segment
		if ((shmid = shmget(KEY, SIZE, 0)) == -1)
		{
			syslog(LOG_ERR, "shmget");
			perror("shmget");
			exit(-1);
		}
	}
	else
	{
		if ((shmid = shmget(KEY, SIZE, IPC_CREAT | 0644)) == -1)
		{
			syslog(LOG_ERR, "shmget");
			perror("shmget");
			exit(-1);
		}
	}

	// assign the segment to the pointer
	string = shmat(shmid, (void *)0, 0);
	if (string == (char *)(-1))
	{
		syslog(LOG_ERR, "shmat");
		perror("shmat");
		exit(-1);
	}

	if(strcmp(action, "write") == 0)
	{
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
	}
	else if(strcmp(action, "read") == 0)
	{
		printf("%s\n", string);
	}

	// detach the segment
	shmdt((void *) string);

	if(strcmp(action, "clear") == 0)
	{
		shmctl(shmid, IPC_RMID, NULL);
	}
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

	setTheInfo(0, "clear");

	exit(3);
}            

