#include "raat.h"

pull *nodes_by_rt_table_id = NULL, *nodes_by_mac = NULL;

int main(int argc, char *argv[])
{
	char *p_argvTmp;

	// initialize struct memory
	push *snd = malloc(sizeof(push));
	flags *f = malloc(sizeof(flags));
	pull *rcv = NULL;

	// reset structs before using
	memset(snd, 0, sizeof(*snd));
	memset(f, 0, sizeof(*f));

	int opt;
	opterr = 0;

	// initial state for options -s, -b and -t 
	f->sleepTime = 10;
	f->breakUp = 5;
	f->dataType = 100;

	while((opt = getopt(argc, argv, "i:wls:b:t:DhI")) != -1)
	{
		switch(opt)
		{
			case 'I':
				f->Iflag = 1;
				break;
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
				f->sleepTime = strtol(optarg, &p_argvTmp, 10);
				break;
			case 'b':
				f->bflag = 1;
				f->breakUp = strtol(optarg, &p_argvTmp, 10);
				break;
			case 't':
				f->tflag = 1;
				f->dataType = strtol(optarg, &p_argvTmp, 10);
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

	// check for alfred
	pid_t alfred_pid = proc_find("alfred");
	if (alfred_pid == -1)
	{
		printf("Are you sure that the alfred exists and running?\n");
		exit(-1);
	}

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

	// install SIGQUIT signal to clear shared memory
	if (signal(SIGQUIT, SIGQUIT_handler) == SIG_ERR) {
		printf("SIGQUIT install error\n");
		exit(2);
	}

	// clear garbage routes before beginning (from raat_pull.c)
	flushRulesRoutes();

	while(1)
	{
		// get if WAN exists (from raat_push.c)
		wanRouteExists(snd);

		// get local LAN routes (from raat_push.c)
		getLocalRoutes(snd);

		// push data to alfred (from raat_push.c)
		pushData(snd, f);

		// see -s option
		sleep(f->sleepTime);

		// pull data (from raat_pull.c)
		getSetRoutes(snd, rcv, f);
		removeExpired(rcv, f);

		// organization table from struct and write it to shared memory
		writeSharedMemory(rcv);
	}
}

void checkArgs(flags *f, push *snd)
{
	int i;

	if(f->Iflag == 1)
	{
		readSharedMemory();
		exit(0);
	}

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
			if(f->dataType < 64 || f->dataType > 255)
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
		printf("	-t 100		Data type in alfred space, from 64 to 255\n");
		printf("	-I		Get the information from shared memory\n");
		printf("	-h		Show this help\n");
		exit(1);
	}
}

// https://github.com/pasce/daemon-skeleton-linux-c
void daemonize(void)
{
	pid_t pid;
    
	// Fork off the parent process
	pid = fork();
    
	// An error occurred 
	if (pid < 0)
		exit(EXIT_FAILURE);
    
	// Success: Let the parent terminate 
	if (pid > 0)
		exit(EXIT_SUCCESS);
    
	// On success: The child process becomes session leader 
	if (setsid() < 0)
		exit(EXIT_FAILURE);
    
	// Catch, ignore and handle signals 
	// TODO: Implement a working signal handler 
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
    
	// Fork off for the second time
	pid = fork();
    
	// An error occurred
	if (pid < 0)
		exit(EXIT_FAILURE);

	// Success: Let the parent terminate
	if (pid > 0)
		exit(EXIT_SUCCESS);

	// Stop if the process already running
	if(setPid() != -1)
	{
		printf("Check for pid file\n");
		exit(EXIT_FAILURE);
	}

	// Set new file permissions
	umask(0);
    
	// Change the working directory to the root directory
	// or another appropriated directory
	chdir("/");
    
	// Close all open file descriptors
	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
	{
		close (x);
	}
    
	// Open the log file
	openlog ("raat", LOG_PID, LOG_DAEMON);
	syslog (LOG_NOTICE, "raat daemon was started.");
}

int setPid(void)
{
	char pidStr[10];
	int pidInt;
	char *p_pid;
	char pidFile[20] = "/var/run/raat.pid";
	FILE* read = fopen(pidFile, "r");
	if(!read)
	{
		FILE *write = fopen(pidFile, "w");
		fprintf(write, "%d", getpid());
		fclose(write);
		return -1;
	}
	else
	{
		if(fgets(pidStr, sizeof(pidStr), read))
		{
			pidInt = strtol(pidStr, &p_pid, 10);
			fclose(read);
			return pidInt;
		}
		else
		{
			fclose(read);
			FILE *write = fopen(pidFile, "w");
			fprintf(write, "%d", getpid());
			fclose(write);
			return -1;
		}
	}
}

// https://stackoverflow.com/a/6898456/5714268
pid_t proc_find(const char* name) 
{
	DIR* dir;
	struct dirent* ent;
	char* endptr;
	char buf[512];

	if (!(dir = opendir("/proc")))
	{
		perror("can't open /proc");
		return -1;
	}

	while((ent = readdir(dir)) != NULL)
	{
		// if endptr is not a null character, the directory is not
		// entirely numeric, so ignore it 
		long lpid = strtol(ent->d_name, &endptr, 10);
		if (*endptr != '\0')
		{
			continue;
		}

		// try to open the cmdline file
		snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
		FILE* fp = fopen(buf, "r");

		if (fp)
		{
			if (fgets(buf, sizeof(buf), fp) != NULL)
			{
				// check the first token in the file, the program name 
				char* first = strtok(buf, " ");
				if (strstr(first, name))
				{
					fclose(fp);
					closedir(dir);
					return (pid_t)lpid;
				}
			}
			fclose(fp);
		}
	}
	closedir(dir);
	return -1;
}

