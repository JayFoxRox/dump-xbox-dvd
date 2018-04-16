// Copyright 2017 Jannik Vogel
// Licensed under GPLv3 or any later version.
// Refer to the LICENSE.txt file included.

// Based on original code by Truman Hy, Jackal and iR0b0t.

#include "ss.h"

#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

static uint32_t psn_to_lba(uint32_t psn) {
  const uint32_t dvd_layerbreak = 0x030000;
  const int32_t layerbreak_offset = 1913776;
  uint32_t xbox_dvd_layerbreak = dvd_layerbreak + layerbreak_offset;
  if(psn < xbox_dvd_layerbreak) {
    // Layer 0 PSN to LBA.
    return psn - dvd_layerbreak;
  } else {
    // Layer 1 PSN to LBA.
    return (xbox_dvd_layerbreak) * 2 - ((psn ^ 0xFFFFFF) + 1) - dvd_layerbreak;
  }
  return 0;
}

// The 2048 byte Xbox1 decrypted security sector file contains 2 copies of the table with sector ranges:
//
// - table 1: 1633 to 1839 (207 bytes)
// - table 2: 1840 to 2046 (207 bytes)
//
// The entries are 9 bytes wide, so there are 9x23 entries (or rows). The sectors are the last 2x3=6 bytes
// of each row. On the Xbox1 there is only 16 sector ranges, so you only need to display the first 16 rows.
void get_ss_ranges(const uint8_t* ss, SSRange* ranges) {
  const uint8_t* cursor1 = &ss[1633];
  const uint8_t* cursor2 = &ss[1840];
  for(unsigned int i = 0; i < 16; i++) {
    //Get PSN (Physical Sector Number).
    assert(!memcmp(cursor1, cursor2, 9));
    ranges[i].start = psn_to_lba((cursor1[3] << 16) | (cursor1[4] << 8) | cursor2[5]);
    ranges[i].end = psn_to_lba((cursor1[6] << 16) | (cursor1[7] << 8) | cursor2[8]);
    cursor1 += 9;
    cursor2 += 9;
  }
}

const SSRange* find_next_ss(const SSRange* ss_ranges, uint32_t offset) {
  for (unsigned int i = 0; i < 16; i++) {
    if (ss_ranges[i].start < offset) {
      continue;
    }
    return &ss_ranges[i];
  }
  return NULL;
}

SSType get_ss_type(const uint8_t* ss) {
  //Get last layer_0 sector PSN
  uint32_t layer0_last_psn = (ss[13] << 16) | (ss[14] << 8) | ss[15];

  switch(layer0_last_psn) {
  case 0x2033AF: return Xbox;
  case 0x20339F: return Xbox360;
  case 0x238E0F: return Xbox360_XGD3;
  default: break;
  }
  return UnknownType;
}



