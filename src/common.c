#include "../include/common.h"

void failwith(const char * message) {
	if(message != NULL) {
		if(errno != 0)
			perror(message);
		else
			fprintf(stderr, "%s\n", message);
	} else {
		fprintf(stderr, "%s\n", "Unknown error occurred!");
	}
	exit(EXIT_FAILURE);
}

void usage(const char * arg_0, const int exit_code) {
	const char * app_name = strrchr(arg_0, '/') + 1;
	if(exit_code != EXIT_SUCCESS) {
		fprintf(stderr, usage_message, app_name);
    } else {
        fprintf(stdout, help_message, app_name);
    }
    exit(exit_code);
}
