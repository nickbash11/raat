#include "raat.h"

void checkArgs(flags *f, push *snd);
void daemonize(void);

int main(int argc, char *argv[])
{
	push *snd = malloc(sizeof(push));
	flags *f = malloc(sizeof(flags));
	pull *rcv = NULL;

	memset(snd, 0, sizeof(*snd));
	memset(f, 0, sizeof(*f));

//	printf("%d %d %d\n", snd->wanRouteExists, snd->wanPublish, snd->lanPublish);
//	printf("%d %d %d %d %d\n", f->hflag, f->wflag, f->lflag, f->sflag, f->sleepTime);

	int opt;
	opterr = 0;

	// initial state for options -s and -b
	f->sleepTime = 10;
	f->breakUp = 5;
	f->dataType = 100;

	while((opt = getopt(argc, argv, "i:wls:b:t:Dh")) != -1)
	{
		switch(opt)
		{
			case 'i':
				f->iflag = 1;
				snprintf(snd->batmanIf, 12, "%s", optarg);
				break;
			case 'w':
				f->wflag = 1;
				break;
			case 'l':
				f->lflag = 1;
				break;
			case 's':
				f->sflag = 1;
				f->sleepTime = strtol(optarg, &f->p_sleepTime, 10);
				break;
			case 'b':
				f->bflag = 1;
				f->breakUp = strtol(optarg, &f->p_breakUp, 10);
				break;
			case 't':
				f->tflag = 1;
				f->dataType = strtol(optarg, &f->p_dataType, 10);
				break;
			case 'D':
				f->Dflag = 1;
				break;
			case 'h':
				f->hflag = 1;
				break;
			case '?':
				if (optopt == 'i')
					fprintf (stderr, "Option -%c requires an argument. Use -h for help\n", optopt);
				else if (optopt == 's')
					fprintf (stderr, "Option -%c requires an argument. Use -h for help\n", optopt);
				else if (optopt == 'b')
					fprintf (stderr, "Option -%c requires an argument. Use -h for help\n", optopt);
				else if (optopt == 't')
					fprintf (stderr, "Option -%c requires an argument. Use -h for help\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'. Use -h for help\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;
		}
	}

	// check arguments
	checkArgs(f, snd);

	// optind is for the extra arguments
	// which are not parsed
	for(; optind < argc; optind++){
		printf("extra arguments: %s\n", argv[optind]);
	}

	// check if the interface exists (from raat_push.c)
	checkBatIf(snd);

	// get BATMAN ipv4 address (from raat_push.c)
	getBatIpAddr(snd);

	// go to daemon
	daemonize();

	// clear garbage routes before beginning (from raat_pull.c)
	flushRulesRoutes();

	while(1)
	{
		// get if WAN exists (from raat_push.c)
		wanRouteExists(snd);

		// get local LAN routes (from raat_push.c)
		getLocalRoutes(snd);

		// open for Alfred's pipe
		char push[1000];
		FILE* alfred = popen("alfred -s 100", "w");

		// put unix timestamp first
		int timestamp = (int)time(NULL);
		char timestampstr[12];
		sprintf(timestampstr, "%d*", timestamp);
		fputs(timestampstr, alfred);

		// put ipv4 address second
		sprintf(push, "%s*", snd->batmanAddr);
		fputs(push, alfred);

		if(snd->wanRouteExists == 0 && snd->p_localRoutes[0] == NULL) {
			fputs("none*", alfred);
		}
	
		if(snd->wanRouteExists == 1) {
			fputs("default*", alfred);
		}

		int i = 0;
		while(snd->p_localRoutes[i] != NULL) {
			sprintf(push, "%s*", snd->p_localRoutes[i]);
			fputs(push, alfred);
			i++;
		}

		pclose(alfred);

		// see -s option
		sleep(f->sleepTime);

		// pull data (from raat_pull.c)
		getAndSetStruct(snd, rcv, f);
		checkStatus(f, rcv);
		removeExpired(rcv, f);
	}

	closelog();
}

void checkArgs(flags *f, push *snd)
{
	int i;

	// -i option
	if(f->iflag == 1)
	{
		if(strlen(snd->batmanIf) < 11 && strlen(snd->batmanIf) > 2)
		{
			for(i = 0; i < strlen(snd->batmanIf); i++)
			{
				if(snd->batmanIf[i] == '!' || snd->batmanIf[i] == '@' || snd->batmanIf[i] == '#' || snd->batmanIf[i] == '$'
				|| snd->batmanIf[i] == '%' || snd->batmanIf[i] == '^' || snd->batmanIf[i] == '&' || snd->batmanIf[i] == '*'
				|| snd->batmanIf[i] == '(' || snd->batmanIf[i] == ')' || snd->batmanIf[i] == '-' || snd->batmanIf[i] == '{'
				|| snd->batmanIf[i] == '}' || snd->batmanIf[i] == '[' || snd->batmanIf[i] == ']' || snd->batmanIf[i] == ':'
				|| snd->batmanIf[i] == ';' || snd->batmanIf[i] == '"' || snd->batmanIf[i] == '\'' || snd->batmanIf[i] == '<'
				|| snd->batmanIf[i] == '>' || snd->batmanIf[i] == '.' || snd->batmanIf[i] == '/' || snd->batmanIf[i] == '?'
				|| snd->batmanIf[i] == '~' || snd->batmanIf[i] == '`' )
				{
					printf("Interface name can't contain special symbols!\n\n");
					f->hflag = 1;	
				}
			}
		}
		else
		{
			printf("Interface name must be in range from 3 to 10 symbols!\n\n");
			f->hflag = 1;
		}
	}
	else
	{
		f->hflag = 1;
	}

	// -w option
	if(f->wflag == 1)
	{
		if(f->iflag == 1)
		{
			snd->wanPublish = 1;
		}
		else
		{
			f->hflag = 1;
		}
	}

	// -l option
	if(f->lflag == 1)
	{
		if(f->iflag == 1)
		{
			snd->lanPublish = 1;
		}
		else
		{
			f->hflag = 1;
		}
	}

	// -s option
	if(f->sflag == 1)
	{
		if(f->iflag == 1)
		{

			if(f->sleepTime < 1 || f->sleepTime > 60)
			{
				f->hflag = 1;
			}
		}
		else
		{
			f->hflag = 1;
		}
	}

	// -b option
	if(f->bflag == 1)
	{
		if(f->iflag == 1)
		{
			if(f->breakUp < 1 || f->breakUp > 30)
			{
				f->hflag = 1;
			}
		}
		else
		{
			f->hflag = 1;
		}
	}

	// -t option
	if(f->tflag == 1)
	{
		if(f->iflag == 1)
		{
			if(f->dataType < 0 || f->dataType > 255)
			{
				f->hflag = 1;
			}
		}
		else
		{
			f->hflag = 1;
		}
	}

	// -D option
	if(f->Dflag == 1)
	{
		if(f->iflag == 1)
		{
			//
		}
		else
		{
			f->hflag = 1;
		}
	}

	// -h option
	if(f->hflag == 1)
	{
		printf("Usage: raat -i bat0\n\n");
		printf("	-i interface	Batman or bridge interface which contains batman\n\t\t\tinterface. This interface's ipv4 address\n\t\t\twill be announced as a route for other nodes\n");
		printf("        -w		Publish WAN interface as a default route\n");
		printf("	-l		Publish LAN routes. For now it finds br-lan interfaces\n");
		printf("	-s 10		Range between push and pull operations\n\t\t\t(default 10 seconds), can be from 1 to 60\n");
		printf("	-b 5		How many times to wait until a node will be\n\t\t\tconsidered as a dead (default 5 times). It\n\t\t\tdepends on -s and can be from 1 to 30\n");
		printf("	-t 100		Data type in alfred space, from 0 to 255\n");
		printf("	-D		Enable debug mode\n");
		printf("	-h		Show this help\n");
		exit(1);
	}
}

void daemonize(void)
{
	pid_t pid;
    
	/* Fork off the parent process */
	pid = fork();
    
	/* An error occurred */
	if (pid < 0)
		exit(EXIT_FAILURE);
    
	/* Success: Let the parent terminate */
	if (pid > 0)
		exit(EXIT_SUCCESS);
    
	/* On success: The child process becomes session leader */
	if (setsid() < 0)
		exit(EXIT_FAILURE);
    
	/* Catch, ignore and handle signals */
	/*TODO: Implement a working signal handler */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
    
	/* Fork off for the second time*/
	pid = fork();
    
	/* An error occurred */
	if (pid < 0)
		exit(EXIT_FAILURE);
    
	/* Success: Let the parent terminate */
	if (pid > 0)
		exit(EXIT_SUCCESS);
    
	/* Set new file permissions */
	umask(0);
    
	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	chdir("/");
    
	/* Close all open file descriptors */
	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
	{
		close (x);
	}
    
	/* Open the log file */
	openlog ("raat", LOG_PID, LOG_DAEMON);
	syslog (LOG_NOTICE, "raat daemon was started.");
}

