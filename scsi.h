// Copyright 2017 Jannik Vogel
// Licensed under GPLv3 or any later version.
// Refer to the LICENSE.txt file included.

#ifndef __SCSI_H__
#define __SCSI_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

extern const size_t SectorSize;

typedef struct {
  unsigned int l0;
  unsigned int l1;
} LayerSizes;

typedef enum {
  #define MODE_LOCKED 0
  Locked = 0,
  #define MODE_XTREME 1
  XTreme = 1,
  #define MODE_WXRIPPER 2
  WxRipper = 2
} LockedState;

int setlockingmode(LockedState state);
int getlayersizes(LayerSizes* layersizes);
int setstreaming();
bool readblock(uint8_t* buffer, unsigned int offset, unsigned int size);
int getfeaturelist(unsigned char* buffer, size_t buffer_size);
int read_dvd_structure(uint8_t* buffer, size_t buffer_size, uint32_t block, uint8_t layer, uint8_t format, uint16_t size, uint8_t unk, uint8_t vendor);
int getpfi(uint8_t layer, uint8_t* buffer, size_t buffer_size);
int getdmi(uint8_t* buffer, size_t buffer_size);
int getss(unsigned char index, unsigned char* buffer, size_t buffer_size);
int inquiry(uint8_t* buffer, size_t buffer_size);

#endif
