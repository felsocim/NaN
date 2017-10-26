#include "../include/capture.h"

char * help_message = "NaN help message";
char * usage_message = "NaN usage message";

int main(int argc, char ** argv)
{
	pcap_t * capture = get_online_capture("enp0s25", NULL);
	switch(init_capture(capture, NB_PACKETS)) {
		case 0:
			printf("Capture successful\n");
			return 0;
		case -1:
			fprintf(stderr, "Error capturing packets!\n");
			return -1;
		case -2:
			fprintf(stderr, "Loop breakout encountered. No packets processed!\n");
			return -2;
	}
	
	return 0;
}
