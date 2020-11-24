#include "raat.h"

#define SIZE 65536
#define SIZE_LOCK 4
#define KEY 7893245
#define KEY_LOCK 8712631

void setTheInfo(pull *rcv, char *action)
{
	int shmid, shmid_lock;
	char *string;
	int  *p_lock, lock = 1, unlock = 0;
	char buf[1024];

	// get the id of segment
	if ((shmid_lock = shmget(KEY_LOCK, SIZE_LOCK, 0644 | IPC_CREAT)) == -1)
	{
		perror("shmget");
		syslog(LOG_ERR, "shmget_lock");
		exit(-1);
	}
 
	// assign the segment to the pointer
	p_lock = shmat(shmid_lock, (int *)0, 0);
	if (p_lock == (int *)(-1))
	{
		perror("shmat");
		syslog(LOG_ERR, "shmat_lock");
		exit(-1);
	}

	// wait while lock is 1
	while(*p_lock == lock)
	{
		// sleep 10 milliseconds
		usleep(10000);
	}

	// set lock to 1
	*p_lock = lock;

	// set the id for payload segment
//	if ((shmid = shmget(KEY, SIZE, 0644 | IPC_CREAT)) == -1)
	if ((shmid = shmget(KEY, SIZE, 0)) == -1)
	{
		syslog(LOG_ERR, "shmget");
		perror("shmget");
		exit(-1);
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

		// copy the content of buffer to the segment
		strcpy(string, "\0");
		strcat(string, "mac			originator		timestamp	ip		default		routes\n");

		for(rcv=nodes_by_mac; rcv != NULL; rcv=rcv->hh2.next)
		{
			sprintf(buf, "%s	%s	%d	%s	%d		%s\n", rcv->mac, rcv->mac, rcv->node_timestamp, rcv->ipv4, rcv->isDefault, rcv->routes);
			strcat(string, buf);
		}
	}
	else if(strcmp(action, "read") == 0)
	{
		printf("%s\n", string);
	}

	// detach the segment
	shmdt((void *) string);

	*p_lock = unlock;
	shmdt(p_lock);
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

