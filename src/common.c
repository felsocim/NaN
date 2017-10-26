#include "../include/common.h"

void failwith(const char * message) {
	if(message != NULL) {
		perror(message);
	} else {
		perror("Error");
	}
	exit(EXIT_FAILURE);
}

void usage(const char * arg_0, const int exit_code) {
	const char * app_name = strrchr(arg_0, '/');
	if(exit_code != 0) {
		fprintf(stderr, usage_message, app_name);
    } else {
        fprintf(stdout, help_message, app_name);
    }
    exit(exit_code);
}
