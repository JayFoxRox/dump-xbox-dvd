// Copyright 2017 Jannik Vogel
// Licensed under GPLv3 or any later version.
// Refer to the LICENSE.txt file included.

#ifndef __SS_H__
#define __SS_H__

#include <stdint.h>

typedef enum {
  UnknownType,
  Xbox,
  Xbox360,
  Xbox360_XGD3
} SSType;

typedef struct {
  uint32_t start;
  uint32_t end;
} SSRange;

const SSRange* find_next_ss(const SSRange* ss_ranges, uint32_t offset);
void get_ss_ranges(const uint8_t* ss, SSRange* ranges);
SSType get_ss_type(const uint8_t* ss);

#endif
