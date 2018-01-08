#ifndef __COMMON_H
#define __COMMON_H

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

extern char * help_message;
extern char * usage_message;

void failwith(const char * message);
void usage(const char * arg_0, const int exit_code);

#endif
