#include "raat.h"

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

