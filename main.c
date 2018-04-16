// Copyright 2017 Jannik Vogel
// Licensed under GPLv3 or any later version.
// Refer to the LICENSE.txt file included.

#include "zlib.h"

#include <assert.h>
#include <inttypes.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crc32.h"

#include "platform.h"

#include "md5.h"
#include "sha1.h"

#include "ss.h"
#include "scsi.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

FILE* iso = NULL;

CRC32_CTX crc32context;
MD5_CTX md5context;
SHA1_CTX sha1context;

bool printprogress(uint32_t totalsize, uint32_t sectorsdone) {
  uint64_t currenttime = millisecondstime();
  static uint64_t starttime = 0;
  static uint64_t lastupdate = 0;
  if (starttime == 0 || lastupdate == 0) {
    starttime = currenttime;
    lastupdate = currenttime;
  }

  if (currenttime > (lastupdate + 10)) {
    uint64_t ms_passed = currenttime - starttime;

    lastupdate = currenttime;

    printf("%" PRIu32 " sectors (%u%%", sectorsdone, ((sectorsdone * 100) / totalsize));
    if (ms_passed > 0) {
      unsigned int rate = ((sectorsdone / 512 * 100000) / ms_passed);
      printf(", %u.%02u MiB/sec", rate / 100, rate % 100);
    }
    printf(")   \r");
    fflush(stdout);
    return true;
  }
  return false;
}


bool processblock(const uint8_t* buffer, size_t buffer_size, bool compress) {
  buffer_size *= SectorSize; // We work in bytes now!

static uint64_t saved = 0;
static uint64_t shitty = 0;

#if 1
  //FIXME: In a thread
  CRC32_Update(&crc32context, buffer, buffer_size);
  MD5_Update(&md5context, buffer, buffer_size);
  SHA1_Update(&sha1context, buffer, buffer_size);

  //FIXME: In a thread
  //FIXME: Better error checking

uint8_t* output_buffer;
size_t output_size;
if (compress) {
  size_t output_buffer_size = buffer_size + 512;
  output_buffer = malloc(output_buffer_size); //FIXME: How much overhead does zlib need in the worst case?!
  z_stream defstream;
  defstream.zalloc = Z_NULL;
  defstream.zfree = Z_NULL;
  defstream.opaque = Z_NULL;
  // setup "a" as the input and "b" as the compressed output
  defstream.avail_in = (uInt)buffer_size; // size of input, string + terminator
  defstream.next_in = (Bytef*)buffer; // input char array
  defstream.avail_out = (uInt)output_buffer_size; // size of output
  defstream.next_out = (Bytef*)output_buffer; // output char array

  deflateInit(&defstream, Z_BEST_COMPRESSION);
  deflate(&defstream, Z_FINISH);

  assert(defstream.avail_in == 0);
  output_size = output_buffer_size - defstream.avail_out;
//  printf("From %d to %d\n", buffer_size, output_size);

  deflateEnd(&defstream);

saved += buffer_size - output_size;
if (output_size == 84) {
  shitty += 1;
}

} else {
  output_buffer = (uint8_t*)buffer;
  output_size = buffer_size;
}

#if 0
  if(fwrite(output_buffer, 1, output_size, iso) != output_size) {

if (compress) {
free(output_buffer);
}

    printf("Error writing..\n");
    return false;
  }
#endif

if (compress) {
  free(output_buffer);
}

printf("Saved: %" PRIu64 "     %" PRIu64 " are shitty\n", saved, shitty);

#endif
  return true;
}

bool dump_sectors(uint32_t start, uint32_t end, bool read_data, const SSRange* ss_ranges, unsigned int* sectorsdone, unsigned int totalsize, bool compress) {
  uint32_t buffer_size = 32;
  uint8_t* buffer = (uint8_t*)malloc(buffer_size * SectorSize);

  if (!read_data) {
    memset(buffer, 0x00, buffer_size * SectorSize);
  }

  uint32_t offset = start;
  while (offset < end) {

    uint32_t data_chunk_size = MIN(end - offset, buffer_size);
    uint32_t skip_size = 0;

    if (ss_ranges != NULL) {
      const SSRange* ss_range = find_next_ss(ss_ranges, offset);
      if (ss_range != NULL) {
        if ((offset + data_chunk_size) >= ss_range->start) {
          data_chunk_size = ss_range->start - offset;
          skip_size = ss_range->end - ss_range->start + 1;
        }
      }
    }

    if (read_data) {
      if (!readblock(buffer, offset, data_chunk_size)) {
        break;
      }
    }
    if (!processblock(buffer, data_chunk_size, compress)) {
      break;
    }

    uint32_t total_chunk_size = data_chunk_size + skip_size;

    // Write padding / zero data
    if (read_data && (skip_size > 0)) {
      memset(buffer, 0x00, buffer_size * SectorSize);
    }
    while(skip_size > 0) {
      uint32_t skip_chunk_size = MIN(skip_size, buffer_size);
      processblock(buffer, skip_chunk_size, compress);
      skip_size -= skip_chunk_size;
    }

    *sectorsdone += total_chunk_size;
    offset += total_chunk_size;

    printprogress(totalsize, *sectorsdone);
  }

  free(buffer);
  return offset == end;
}

int dump_data(SSRange* ss_ranges) {
  size_t l0_video, l1_video, middlezone, gamedata, totalsize;
  LayerSizes layers;

  bool compress = false;

  if (setlockingmode(MODE_LOCKED)) return 1;
  if (getlayersizes(&layers)) return 1;
  l0_video = layers.l0;
  l1_video = layers.l1;

  if (setlockingmode(MODE_XTREME)) return 1;
  if (getlayersizes(&layers)) return 1;
  gamedata = layers.l0 + layers.l1;

  if (setlockingmode(MODE_WXRIPPER)) return 1;
  if (getlayersizes(&layers)) return 1;
  if (layers.l1 < gamedata) {
    fprintf(stderr, "Error: Middle Zone has a negative value!\n");
    return 1;
  }

  middlezone = layers.l1 - gamedata;
  totalsize = l0_video + l1_video + (2 * middlezone) + gamedata;

  printf("\n");
  printf("L0 Video Size: %zu sectors\n", l0_video);
  printf("L1 Video Size: %zu sectors\n", l1_video);
  printf("Middle Zone Size: %zu sectors\n", middlezone);
  printf("Game Data Size: %zu sectors\n", gamedata);
  printf("Total Size: %zu sectors (%" PRIu64 " bytes = %.1f GiB)\n", totalsize, totalsize * (uint64_t)SectorSize, totalsize * (float)SectorSize / 1024.0f / 1024.0f / 1024.0f);
  printf("\n");
  printf("Real Layer Break: %zu sectors\n", l0_video + middlezone + (gamedata / 2));
  printf("\n");

  unsigned int sectorsdone = 0;

  if (setstreaming()) {
    return 1;
  }

  // L0 Video
  dump_sectors(0, l0_video, true, NULL, &sectorsdone, totalsize, compress);

  // Middle Zone A
  dump_sectors(l0_video, l0_video + middlezone, false, NULL, &sectorsdone, totalsize, compress);

  // Game Data
  dump_sectors(l0_video + middlezone, l0_video + middlezone + gamedata, true, ss_ranges, &sectorsdone, totalsize, compress);

  // Middle Zone D
  dump_sectors(0, middlezone, false, NULL, &sectorsdone, totalsize, compress);

  // L1 Video
  if (setlockingmode(MODE_LOCKED)) {
    return 1;
  }
  dump_sectors(l0_video, l0_video + l1_video, true, NULL, &sectorsdone, totalsize, compress);

  //FIXME: Why do this? Comes from freecell..
  if (setlockingmode(MODE_WXRIPPER)) {
    return 1;
  }

  return 0;
}

void digesttostr(char *hash, const uint8_t* digest, size_t length) {
  const char* hex_digits = "0123456789ABCDEF";
  for (unsigned int i = 0; i < length; i++) {
    hash[(i * 2) + 0] = hex_digits[digest[i] >> 4];
    hash[(i * 2) + 1] = hex_digits[digest[i] & 0xF];
  }
  hash[length * 2] = 0;
}


uint32_t calculate_crc(uint8_t* buffer, size_t buffer_size) {
  CRC32_CTX ctx;
  unsigned int crc;
  CRC32_Init(&ctx);
  CRC32_Update(&ctx, buffer, buffer_size);
  CRC32_Final(&crc, &ctx);
  return crc;
}

void dump_file(const char* path, const uint8_t* buffer, size_t buffer_size) {
  FILE* f = fopen(path, "wb");
  fwrite(buffer, buffer_size, 1, f);
  fclose(f);
}

const char* get_kreon_feature_description(uint16_t feature) {
  switch(feature) {
  case 0x0100: return "Xbox 360 unlock 1 state (xtreme)";
  case 0x0101: return "Xbox 360 unlock 2 state (wxripper)";
  case 0x0120: return "Xbox 360 SS reading and decryption";
  case 0x0121: return "Xbox 360 full challenge response functionality";
  case 0x0200: return "Xbox unlock 1 state (xtreme)";
  case 0x0201: return "Xbox unlock 2 state (wxripper)";
  case 0x0220: return "Xbox SS reading and decryption";
  case 0x0221: return "Xbox 360 full challenge response functionality";
  case 0xF000: return "Lock command (cancel unlock)";
  case 0xF001: return "Error skipping";
  default: break;
  }
  return NULL;
}

const char* executable = NULL;
int main(int argc, char *argv[]) {
  executable = argv[0];
  int ret = 0;

  int optind = 1;
  if (getdrive(argv[optind])) {
    fprintf(stderr, "%s: %s does not look like a valid drive\n", executable, argv[optind]);
    return 1;
  }
  optind++;

  if (opendrive()) {
    return 1;
  }

  uint8_t buffer[4096];

  //FIXME: Get info about drive
  inquiry(buffer, 255);
  //dump_file("inquiry.bin", buffer, 255);

  char vendor_identification[8+1] = {0};
  memcpy(vendor_identification, &buffer[8], sizeof(vendor_identification) - 1);
  printf("Vendor Identification: '%s'\n", vendor_identification);

  char product_identification[16+1] = {0};
  memcpy(product_identification, &buffer[16], sizeof(product_identification) - 1);
  printf("Product Identification: '%s'\n", product_identification);

  char product_revision_level[4+1] = {0};
  memcpy(product_revision_level, &buffer[32], sizeof(product_revision_level) - 1);
  printf("Product Revision Level: '%s'\n", product_revision_level);

  char vendor_specific[20+1] = {0};
  memcpy(vendor_specific, &buffer[36], sizeof(vendor_specific) - 1);
  printf("Vendor Specific: '%s'\n", vendor_specific);

  printf("\n");

  if (!strcmp(vendor_specific, "KREON V1.00")) {
    printf("Kreon 1.00 detected!\n");
    printf("Kreon features:\n");

    uint8_t buffer[4096];
    getfeaturelist(buffer, sizeof(buffer));

    const uint16_t* feature = (uint16_t*)buffer;
    //FIXME: Watch out for overflow!
    assert(*feature++ == htons(0xA55A));
    assert(*feature++ == htons(0x5AA5));
    while(*feature != 0x0000) {
      printf("- %s\n", get_kreon_feature_description(htons(*feature)));
      feature++;
    }
  } else {
    printf("Unknown drive!\n");
    //FIXME: Inform user which firmware might be applicable for their drive
  }
  printf("\n");

  //FIXME: Get layer sizes and test if locking works properly
  setlockingmode(MODE_XTREME);

//  memset(buffer, 0xAA, sizeof(buffer));
//  getfeaturelist(buffer, sizeof(buffer));

  // Dump the typical piracy related files
  if (1) {
    memset(buffer, 0xAA, sizeof(buffer));
    getdmi(buffer, sizeof(buffer));
    dump_file("DMI.bin", &buffer[4], 2048);
    printf("DMI: %08X\n", calculate_crc(&buffer[4], 2048));
  }

  if (1) {
    memset(buffer, 0xAA, sizeof(buffer));
    getpfi(0, buffer, sizeof(buffer));
    dump_file("PFI.bin", &buffer[4], 2048);

    printf("PFI: %08X\n", calculate_crc(&buffer[4], 2048));
  }

  uint8_t ss[2048];
  if (1) {
    //FIXME: I have no idea how to do this correctly?!
    memset(buffer, 0xAA, sizeof(ss));
    getss(0x01, ss, sizeof(ss)); // Expected checksum
    //getss(0x03, buffer, sizeof(buffer)); // Expected checksum
    //getss(0x05, buffer, sizeof(buffer)); // Expected checksum
    //getss(0x07, buffer, sizeof(buffer)); // Expected checksum
    dump_file("SS.bin", ss, sizeof(ss));

    printf("SS: %08X\n", calculate_crc(ss, sizeof(ss)));
  }

  printf("\n");

  SSType ss_type = get_ss_type(ss);
  if (ss_type == Xbox360 || ss_type == Xbox360_XGD3) {
    fprintf(stderr, "This seems to be an Xbox 360 disc. This tool is only capable of dumping original Xbox discs!\n");
    return 1;
  } else if (ss_type != Xbox) {
    fprintf(stderr, "This does not seem to be an original Xbox disc!\n");
    return 1;
  }
  
  SSRange ss_ranges[16];
  get_ss_ranges(ss, ss_ranges);

  {
    FILE* f = fopen("sectors.txt", "wb");
    for(unsigned int i = 0; i < 16; i++) {
      printf("%" PRIu32 "-%" PRIu32 "\r\n", ss_ranges[i].start, ss_ranges[i].end);
      fprintf(f, "%" PRIu32 "-%" PRIu32 "\r\n", ss_ranges[i].start, ss_ranges[i].end);
      assert(((i == 0) ? 0 : ss_ranges[i - 1].end) <= ss_ranges[i].start);
    }
    fclose(f);
  }

  printf("\n");

  {
    iso = fopen("data.iso", "wb");

    CRC32_Init(&crc32context);
    MD5_Init(&md5context);
    SHA1_Init(&sha1context);

    dump_data(ss_ranges);

    unsigned int crc;
    CRC32_Final(&crc, &crc32context);

    unsigned char md5digest[MD5_DIGEST_LENGTH];
    char md5hash[(MD5_DIGEST_LENGTH * 2) + 1];
    MD5_Final(md5digest, &md5context);
    digesttostr(md5hash, md5digest, MD5_DIGEST_LENGTH);

    unsigned char sha1digest[SHA1_DIGEST_LENGTH];
    char sha1hash[(SHA1_DIGEST_LENGTH * 2) + 1];
    SHA1_Final(sha1digest, &sha1context);
    digesttostr(sha1hash, sha1digest, SHA1_DIGEST_LENGTH);

    printf("CRC32: %08x\n", (unsigned int)crc);
    printf("MD5:   %s\n", md5hash);
    printf("SHA1:  %s\n", sha1hash);

    fclose(iso);
  } 

  closedrive();

  return ret;
}
