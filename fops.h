#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <sys/syslimits.h>
#include <assert.h>

typedef struct _fops_type {
	unsigned char *data;
	size_t length;
	int in_use;
} FOPS_TYPE;

FOPS_TYPE fops_read(char *path);
