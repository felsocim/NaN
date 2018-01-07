#include "../include/main.h"

char * help_message = "Network traffic analysis.\nUsage: %s -i <interface> | -o <trace dump> [-f <BFP filter>] -v <verbosity level> [-h]\n Option -h shows this help message.\nDeveloped by Marek Felsoci within studies project. Licensed under MIT License.\nNO WARRANTY! FOR EDUCATIONAL PURPOSES ONLY!\n";
char * usage_message = "Arguments mismatch!\nUsage: %s -i <interface> | -o <trace dump> [-f <BFP filter>] -v <verbosity level> [-h]\n";

pcap_t * capture = NULL;

void finish(int signum) {
	if(capture != NULL) {
		printf("\nCapture halt.\n");
		pcap_breakloop(capture);
		return;
	}

	printf("Closing without capture.");
}

int main(int argc, char ** argv)
{
	char * interface = NULL, * trace = NULL, * filter = NULL;
	u_char verbosity = 0;
  int c = 0;
	struct sigaction close;
  sigset_t set;

  sigemptyset(&set);
	close.sa_handler = finish;
  close.sa_flags = SA_NODEFER;
  close.sa_mask = set;

	if(sigaction(SIGINT, &close, NULL) != 0)
		failwith("Failed to set close signal");

	while((c = getopt(argc, argv, "i:o:f:v:h")) != EOF) {
		switch(c) {
			case 'i':
				if (trace != NULL)
					failwith("The -i and -o options can not be used simultaneously!");

				interface = (char *) malloc((strlen(optarg) + 1) * sizeof(char));
				interface = strcpy(interface, optarg);
				break;
			case 'o':
				if (interface != NULL)
					failwith("The -i and -o options can not be used simultaneously!");

				trace = (char *) malloc(PATH_MAX * sizeof(char));

				if(strlen(optarg) > PATH_MAX)
					failwith("The input trace file name you've provided is too long! Check your operating system file name limitations.");

				trace = strcpy(trace, optarg);
				break;
			case 'f':
				filter = (char *) malloc(strlen(optarg) * sizeof(char));
				filter = strcpy(filter, optarg);
				break;
			case 'v':
				verbosity = (u_char) optarg[0];

				if(verbosity < VERBOSITY_LOW || verbosity > VERBOSITY_HIGH)
					failwith("The choosen verbosity level is not supported! Please choose a value from 1 (least verbose) to 3 (most verbose).");
				break;
			case 'h':
				if(interface != NULL)
					free(interface);
				if(trace != NULL)
					free(trace);
				if(filter != NULL)
					free(filter);

				usage(argv[0], EXIT_SUCCESS);
			case '?':
			default:
				usage(argv[0], EXIT_FAILURE);
		}
	}

	if((interface == NULL && trace == NULL) || verbosity == 0)
		usage(argv[0], EXIT_FAILURE);

	if(interface != NULL) { // Live capture (TODO: condition may be not neccessary if we wanna be able to choose the default interface)
		capture = get_online_capture(interface, filter);
	}


	if(trace != NULL) { // Offline capture
		capture = get_offline_capture(trace);
	}

  if(capture != NULL) {
	  switch(init_capture(capture, NUMBER_OF_PACKETS, verbosity)) {
		  case 0:
			  printf("Capture successful\n");
			  break;
		  case -1:
			  if(interface != NULL)
				  free(interface);
			  if(trace != NULL)
				  free(trace);
			  if(filter != NULL)
				  free(filter);

			  failwith("Traffic capture failed");
	  }
  }

  pcap_close(capture);
	if(interface != NULL)
		free(interface);
	if(trace != NULL)
		free(trace);
	if(filter != NULL)
		free(filter);

	return 0;
}
