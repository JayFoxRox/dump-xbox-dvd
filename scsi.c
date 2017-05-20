// Copyright 2017 Jannik Vogel
// Licensed under GPLv3 or any later version.
// Refer to the LICENSE.txt file included.

#include "scsi.h"

#include "platform.h"

#include <stdio.h>
#include <string.h>

const size_t SectorSize = 2048;

int setlockingmode(LockedState state) {
  unsigned char cdb[5];
  unsigned char buffer[2048];
  unsigned int sense;

  cdb[0] = 0xff;
  cdb[1] = 0x08;
  cdb[2] = 0x01;
  cdb[3] = 0x11;
  cdb[4] = state;
  if (sendcdb(cdb, sizeof(cdb), buffer, sizeof(buffer), 1, &sense)) {
    fprintf(stderr, "Error: LOCKING MODE failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for LOCKING MODE.\n");
    return 1;
  }

  return 0;
}

int getlayersizes(LayerSizes* layersizes) {
  unsigned int totallength;
  unsigned int startsector;
  unsigned int endsector;
  unsigned int numberoflayers;
  unsigned char buffer[2048];
  unsigned int sense;

  if (sendcdb((const unsigned char []){0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 10, buffer, sizeof(buffer), 1, &sense)) {
    fprintf(stderr, "Error: READ CAPACITY failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for READ CAPACITY.\n");
    return 1;
  }
  totallength = ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]) + 1;

  if (sendcdb((const unsigned char []){0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00}, 12, buffer, sizeof(buffer), 1, &sense)) {
    fprintf(stderr, "Error: READ DISC STRUCTURE failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for READ DISC STRUCTURE.\n");
    return 1;
  }
  numberoflayers = ((buffer[6] >> 5) & 0x3) + 1;
  startsector = (buffer[9] << 16) | (buffer[10] << 8) | buffer[11];
  endsector = (buffer[17] << 16) | (buffer[18] << 8) | buffer[19];

  if (numberoflayers == 1) {
    layersizes->l0 = totallength;
    layersizes->l1 = 0;
  } else {
    layersizes->l0 = (endsector - startsector) + 1;
    layersizes->l1 = (totallength - layersizes->l0);
  }
  return 0;
}

int setstreaming() {
  unsigned char buffer[28];
  unsigned int sense;

  memset(buffer, 0, 28);

  buffer[12] = 0xff;
  buffer[13] = 0xff;
  buffer[14] = 0xff;
  buffer[15] = 0xff;

  buffer[18] = 0x03;
  buffer[19] = 0xe8;

  buffer[20] = 0xff;
  buffer[21] = 0xff;
  buffer[22] = 0xff;
  buffer[23] = 0xff;

  buffer[26] = 0x03;
  buffer[27] = 0xe8;

  if (sendcdb((const unsigned char []){0xb6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00}, 12, buffer, 28, 0, &sense)) {
    fprintf(stderr, "Error: SET STREAMING failed.\n");
    return 1;
  }

  return 0;
}

bool readblock(uint8_t* buffer, unsigned int offset, unsigned int size) {
  int retry;
  unsigned int sense = 0;
  unsigned char read10[10] = {0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char read12[12] = {0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00};

  retry = 0;
  read10[2] = (offset & 0xff000000) >> 24;
  read10[3] = (offset & 0x00ff0000) >> 16;
  read10[4] = (offset & 0x0000ff00) >> 8;
  read10[5] = (offset & 0x000000ff);
  read10[7] = (size & 0xff00) >> 8;
  read10[8] = (size & 0x00ff);
  do {
    if (sendcdb(read10, 10, buffer, size * SectorSize, 1, &sense)) {
      fprintf(stderr, "Error: MMC READ 10 failed.\n");
      return false;
    }
    retry++;
  } while ((sense != 0) && (retry < 5));
  if (sense == 0) {
    return true;
  }

  retry = 0;
  read12[2] = (offset & 0xff000000) >> 24;
  read12[3] = (offset & 0x00ff0000) >> 16;
  read12[4] = (offset & 0x0000ff00) >> 8;
  read12[5] = (offset & 0x000000ff);
  read12[8] = (size & 0xff00) >> 8;
  read12[9] = (size & 0x00ff);
  do {
    if (sendcdb(read12, 12, buffer, size * SectorSize, 1, &sense)) {
      fprintf(stderr, "Error: MMC READ 12 failed.\n");
      return false;
    }
    retry++;
  } while ((sense != 0) && (retry < 5));
  if (sense == 0) {
    return true;
  }

  fprintf(stderr, "Error: Sense error.\n");
  return false;
}



int getfeaturelist(unsigned char* buffer, size_t buffer_size) {
  unsigned char cdb[] = { 0xFF, 0x08, 0x01, 0x10 };
  unsigned int sense;

  if (sendcdb(cdb, sizeof(cdb), buffer, buffer_size, 1, &sense)) {
    fprintf(stderr, "Error: ss failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for ss.\n");
    return 1;
  }

  return 0;
}

int read_dvd_structure(uint8_t* buffer, size_t buffer_size, uint32_t block, uint8_t layer, uint8_t format, uint16_t size, uint8_t unk, uint8_t vendor) {
  unsigned int sense;

  unsigned char cdb[12];
  cdb[0] = 0xAD;
  cdb[1] = 0x00;
  cdb[2] = block >> 24;
  cdb[3] = (block >> 16) & 0xFF;
  cdb[4] = (block >> 8) & 0xFF;
  cdb[5] = block & 0xFF;
  cdb[6] = layer;
  cdb[7] = format;
  cdb[8] = size >> 8;
  cdb[9] = size & 0xFF;
  cdb[10] = unk;
  cdb[11] = vendor;

  if (sendcdb(cdb, sizeof(cdb), buffer, buffer_size, 1, &sense)) {
    fprintf(stderr, "Error: dvd struc failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for dvd struc.\n");
    return 1;
  }

  return 0;
}

int getpfi(uint8_t layer, uint8_t* buffer, size_t buffer_size) {
  return read_dvd_structure(buffer, buffer_size, 0, layer, 0, 2048 + 4, 0, 0);
//  return read_dvd_structure(buffer, buffer_size, 0xfffd02ff, layer, 0xFE, 0x664, 0xC0);
}

int getdmi(uint8_t* buffer, size_t buffer_size) {
//  return read_dvd_structure(buffer, buffer_size, 0, layer, 4, 0x664, 0);
//  return read_dvd_structure(buffer, buffer_size, 0xfffd02ff, 0xFE, 4, 2048, 0xC0);
  return read_dvd_structure(buffer, buffer_size, 0, 0, 4, 2048 + 4, 0, 0);
}

int getss(unsigned char index, unsigned char* buffer, size_t buffer_size) {
  return read_dvd_structure(buffer, buffer_size, 0xFF02FDFF, 0xFE, 0, 2048, index, 0xC0);
}

int inquiry(uint8_t* buffer, size_t buffer_size) {
  unsigned int sense;

  unsigned char cdb[6];
  cdb[0] = 0x12; // Operation Code
  cdb[1] = 0x00; // Logical Unit Number, Reserved, EVPD
  cdb[2] = 0x00; // Page Code
  cdb[3] = 0x00; // Reserved
  cdb[4] = buffer_size; // Allocation Length
  cdb[5] = 0x00; // Control

  if (sendcdb(cdb, sizeof(cdb), buffer, buffer_size, 1, &sense)) {
    fprintf(stderr, "Error: dvd struc failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for dvd struc.\n");
    return 1;
  }

  return 0;
}
