// Copyright 2017 Jannik Vogel
// Licensed under GPLv3 or any later version.
// Refer to the LICENSE.txt file included.

#ifndef FREECELL_PLATFORM_H
#define FREECELL_PLATFORM_H

extern const char* executable;

int getdrive(char *);
int opendrive();
void closedrive();
unsigned long long millisecondstime();
int sendcdb(const unsigned char *cdb, unsigned char cdblength, unsigned char *buffer, size_t size, int in, unsigned int *sense);

#endif
