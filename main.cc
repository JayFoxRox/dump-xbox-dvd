/*
  This is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this software.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  This software is using crcutil-1.0 for providing fast crc calculations
  crcutil is made by Andrew Kadatch and Bob Jenkins and can be found on http://code.google.com/p/crcutil/
  Do not contact them for support on this software

  Also, this software makes use of the MD5 implementation of Alexander Peslyak.
  This is found at http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
  Changes were made for OpenSSL compatibility and a small casting patch for g++ support.
  These changes are released under the same license as the original md5.c file.

  Finally, this software makes use of the SHA1 implementation of Steve Reid, Ralph Giles et al.
  Changes were made for OpenSSL compatibility and using standard c types in the header.
  Also, SHA1HANDSOFF is defined to protect input data.
  These changes are also released under the same license as the original sha1.c file.
*/

// Usage: FreeCell <DRIVE> [-n|-o OUTPUTFILE] [SECTORFILE]

#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include "windows.h"
#elif defined(__APPLE__)
#include "macosx.h"
#include "crc32.h"
#else
#include "linux.h"
#endif

#ifndef __APPLE__
#include "interface.h"
#endif
#include "md5.h"
#include "sha1.h"

#define OUTPUTFILE "Track 01.iso"
#define SECTORFILE "sectors.txt"

#define SECTORS 32
#define SECTORSIZE 2048
#define BUFFERSIZE (SECTORS * SECTORSIZE)

#define POLY 0xedb88320

#define STATE_ERROR -1
#define STATE_FIRSTVALUE 0
#define STATE_FIRSTVALUEEND 1
#define STATE_MINUS 2
#define STATE_SECONDVALUE 3
#define STATE_SECONDVALUEEND 4
#define STATE_ENDOFLINE 5

#define MODE_LOCKED 0
#define MODE_XTREME 1
#define MODE_WXRIPPER 2

typedef struct {
  unsigned int start;
  unsigned int end;
} sectorrange_t;

typedef struct {
  size_t l0;
  size_t l1;
} layersize_t;

const char *outputfile;
int fd;

sectorrange_t *securitysectors;
int sectorranges;

#ifndef __APPLE__
crcutil_interface::CRC *crcutil;
unsigned long long crc;
#else
CRC32_CTX crc32context;
unsigned int crc;
#endif

MD5_CTX md5context;
SHA1_CTX sha1context;

int readsectorfile(const char *);
int digesttostr(char *, const unsigned char *, size_t);
void usage();
int freecell();
void printprogress(unsigned int, unsigned int);
unsigned int getnextgap(unsigned int);
unsigned int getgapsize(unsigned int);
int setlockingmode(unsigned char);
int getlayersizes(layersize_t *);
int setstreaming();
int readblock(unsigned char *, unsigned int, size_t);
int processblock(const unsigned char *, size_t);

int main(int argc, char *argv[]) {
  int option, nooutput, ret;
  const char *sectorfile;
  unsigned char md5digest[MD5_DIGEST_LENGTH];
  unsigned char sha1digest[SHA1_DIGEST_LENGTH];
  char md5hash[(MD5_DIGEST_LENGTH * 2) + 1];
  char sha1hash[(SHA1_DIGEST_LENGTH * 2) + 1];

  fd = 0;
  nooutput = 0;
  outputfile = NULL;
  sectorfile = NULL;

  while ((option = getopt(argc, argv, "no:h?")) != -1) {
    switch (option) {
      case 'n':
        if (outputfile) {
          fprintf(stderr, EXECUTABLE ": -n option can not be used together with -o\n");
          return 1;
        }
        nooutput = 1;
        break;
      case 'o':
        if (nooutput) {
          fprintf(stderr, EXECUTABLE ": -p option can not be used together with -n\n");
          return 1;
        }
        outputfile = optarg;
        break;
      case 'h':
      case '?':
      default:
        usage();
        return 1;
    }
  }

  if (argc <= optind || argc >= optind + 3) {
    usage();
    return 1;
  }
  
  if (getdrive(argv[optind])) {
    fprintf(stderr, EXECUTABLE ": %s does not look like a valid drive\n", argv[optind]);
    return 1;
  }
  optind++;

  if (argc <= optind + 1) {
    sectorfile = argv[optind];
  }

  if (!nooutput && outputfile == NULL) outputfile = OUTPUTFILE;
  if (sectorfile == NULL) sectorfile = SECTORFILE;

  if (readsectorfile(sectorfile)) return 1;

  if (opendrive()) {
    if (securitysectors != NULL) free(securitysectors);
    return 1;
  }

  if ((outputfile != NULL) && ((fd = open(outputfile, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) == -1)) {
    perror(outputfile);
    closedrive();
    if (securitysectors != NULL) free(securitysectors);
    return 1;
  }

#ifndef __APPLE__
  crcutil = crcutil_interface::CRC::Create(POLY, 0, 32, true, 0, 0, 0, 0, NULL);
  crc = 0;
#else
  CRC32_Init(&crc32context);
#endif
  MD5_Init(&md5context);
  SHA1_Init(&sha1context);

  ret = freecell();

  if (!ret) {
#ifdef __APPLE__
    CRC32_Final(&crc, &crc32context);
#endif
    MD5_Final(md5digest, &md5context);
    SHA1_Final(sha1digest, &sha1context);

    digesttostr(md5hash, md5digest, MD5_DIGEST_LENGTH);
    digesttostr(sha1hash, sha1digest, SHA1_DIGEST_LENGTH);

    printf("CRC32: %08x\n", (unsigned int)crc);
    printf("MD5:   %s\n", md5hash);
    printf("SHA1:  %s\n", sha1hash);
  }

#ifndef __APPLE__
  crcutil->Delete();
#endif
  if (fd) close(fd);
  closedrive();
  if (securitysectors != NULL) free(securitysectors);

  return ret;
}

int readsectorfile(const char *sectorfile) {
  int sectorfd, bytesread, state;
  unsigned char byte;
  sectorrange_t *reallocation;

  securitysectors = NULL;
  sectorranges = 0;

  if ((sectorfd = open(sectorfile, O_RDONLY | O_BINARY)) == -1) {
    perror(sectorfile);
    return 1;
  }

  state = STATE_FIRSTVALUE;
  while ((bytesread = read(sectorfd, &byte, 1)) == 1) {
    if (state == STATE_FIRSTVALUE) {
      if (byte == ' ' || byte == '\r' || byte == '\n') continue;
      if (byte >= '1' && byte <= '9') {
        if((reallocation = (sectorrange_t *)realloc(securitysectors, sizeof(sectorrange_t) * (sectorranges + 1))) == NULL) {
          fprintf(stderr, "Sectors realloc failed. Out of memory?\n");
          return 1;
        }
        securitysectors = reallocation;
        memset(&securitysectors[sectorranges], 0, sizeof(sectorrange_t));
        sectorranges++;
        securitysectors[sectorranges - 1].start = byte - '0';
        state = STATE_FIRSTVALUEEND;
        continue;
      }
      state = STATE_ERROR;
      break;
    }

    if (state == STATE_FIRSTVALUEEND) {
      if (byte >= '0' && byte <= '9') {
        if ((securitysectors[sectorranges - 1].start < 429496729) || (securitysectors[sectorranges - 1].start == 429496729 && byte < '6')) {
          securitysectors[sectorranges - 1].start *= 10;
          securitysectors[sectorranges - 1].start += byte - '0';
          continue;
        }
        state = STATE_ERROR;
        break;
      }
      if (byte == ' ') {
        state = STATE_MINUS;
        continue;
      }
      if (byte == '-') {
        state = STATE_SECONDVALUE;
        continue;
      }
    }

    if (state == STATE_MINUS) {
      if (byte == ' ') continue;
      if (byte == '-') {
        state = STATE_SECONDVALUE;
        continue;
      }
      state = STATE_ERROR;
      break;
    }

    if (state == STATE_SECONDVALUE) {
      if (byte == ' ') continue;
      if (byte >= '1' && byte <= '9') {
        securitysectors[sectorranges - 1].end = byte - '0';
        state = STATE_SECONDVALUEEND;
        continue;
      }
      state = STATE_ERROR;
      break;
    }

    if (state == STATE_SECONDVALUEEND) {
      if (byte >= '0' && byte <= '9') {
        if ((securitysectors[sectorranges - 1].end < 429496729) || (securitysectors[sectorranges - 1].end == 429496729 && byte < '6')) {
          securitysectors[sectorranges - 1].end *= 10;
          securitysectors[sectorranges - 1].end += byte - '0';
          continue;
        }
        state = STATE_ERROR;
        break;
      }
      if (byte == ' ') {
        state = STATE_ENDOFLINE;
        continue;
      }
      if (byte == '\r' || byte == 'n') {
        state = STATE_FIRSTVALUE;
        continue;
      }
      state = STATE_ERROR;
      break;
    }

    if (state == STATE_ENDOFLINE) {
      if (byte == ' ') continue;
      if (byte == '\r' || byte == 'n') {
        state = STATE_FIRSTVALUE;
        continue;
      }
      state = STATE_ERROR;
      break;
    }
  }

  close(sectorfd);

  if ((state != STATE_FIRSTVALUE) && (state != STATE_ENDOFLINE)) {
    fprintf(stderr, "Sector file data corrupt.\n");
    return 1;
  }

  if (bytesread != 0) {
    perror(sectorfile);
    return 1;
  }

  return 0;
}

int digesttostr(char *hash, const unsigned char *digest, size_t length) {
  unsigned int i;

  for (i = 0; i < length; i++) {
    hash[(i * 2)] = ((digest[i] & 0xf0) >> 4) + '0';
    if (hash[(i * 2)] > '9') hash[(i * 2)] += ('a' - '9' - 1);
    hash[(i * 2) + 1] = (digest[i]  & 0x0f) + '0';
    if (hash[(i * 2) + 1] > '9') hash[(i * 2) + 1] += ('a' - '9' - 1);
  }

  hash[length * 2] = 0;
  return length;
}

void usage() {
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: " PROGRAMNAME " " DRIVEUSAGE " [-n|-o OUTPUTFILE] [SECTORFILE]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Dumps an XGD from a compatible drive, padding sectors in SECTORFILE.\n");
  fprintf(stderr, "The resulting OUTPUTFILE will include all video layers data.\n");
  fprintf(stderr, "Outputs the crc, md5 and sha1 of the resulting dump.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -n             don't save to OUTPUTFILE, only calculate and show hashes\n");
  fprintf(stderr, "                 can not be used together with -o\n");
  fprintf(stderr, "  -o OUTPUTFILE  use OUTPUTFILE as file to extract to\n");
  fprintf(stderr, "                 if no -o option is given, it will default to \"Track 01.iso\"\n");
  fprintf(stderr, "                 can not be used together with -n\n");
  fprintf(stderr, "\n");
}

int freecell() {
  size_t l0_video, l1_video, middlezone, gamedata, totalsize;
  layersize_t layers;
  unsigned int offset, sectorsdone, nextgap, gapsize;
  unsigned char buffer[BUFFERSIZE];

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
  printf("L0 Video Size: " SIZE_T_FORMAT "\n", l0_video);
  printf("L1 Video Size: " SIZE_T_FORMAT "\n", l1_video);
  printf("Middle Zone Size: " SIZE_T_FORMAT "\n", middlezone);
  printf("Game Data Size: " SIZE_T_FORMAT "\n", gamedata);
  printf("Total Size: " SIZE_T_FORMAT "\n", totalsize);
  printf("\n");
  printf("Real Layer Break: " SIZE_T_FORMAT "\n", l0_video + middlezone + (gamedata / 2));
  printf("\n");
  fflush(stdout);

  sectorsdone = 0;
  offset = 0;

  if (setstreaming()) return 1;

  // L0 Video
  while ((offset + SECTORS) < l0_video) {
    if (readblock(buffer, offset, BUFFERSIZE)) return 1;
    if (processblock(buffer, BUFFERSIZE)) return 1;
    sectorsdone += SECTORS;
    offset += SECTORS;
    printprogress(totalsize, sectorsdone);
  }
  if (offset < l0_video) {
    if (readblock(buffer, offset, (l0_video - offset) * SECTORSIZE)) return 1;
    if (processblock(buffer, (l0_video - offset) * SECTORSIZE)) return 1;
    sectorsdone += (l0_video - offset);
    offset += (l0_video - offset);
    printprogress(totalsize, sectorsdone);
  }

  // Middle Zone A
  memset(buffer, 0, BUFFERSIZE);
  while ((offset + SECTORS) < (l0_video + middlezone)) {
    if (processblock(buffer, BUFFERSIZE)) return 1;
    sectorsdone += SECTORS;
    offset += SECTORS;
    printprogress(totalsize, sectorsdone);
  }
  if (offset < (l0_video + middlezone)) {
    if (processblock(buffer, ((l0_video + middlezone) - offset) * SECTORSIZE)) return 1;
    sectorsdone += (l0_video + middlezone) - offset;
    offset += (l0_video + middlezone) - offset;
    printprogress(totalsize, sectorsdone);
  }

/*
  while ((offset + SECTORS) < (l0_video + middlezone)) {
    if (readblock(buffer, offset, BUFFERSIZE)) return 1;
//    if ((buffer[0] != 0) || memcmp(buffer, buffer + 1, BUFFERSIZE - 1)) {
//      fprintf(stderr, "Error: Data found in Middle Zone A! Report this as soon as possible please!\n");
//      return 1;
//    }
    if (processblock(buffer, BUFFERSIZE)) return 1;
    sectorsdone += SECTORS;
    offset += SECTORS;
    printprogress(totalsize, sectorsdone);
  }
  if (offset < (l0_video + middlezone)) {
    if (readblock(buffer, offset, ((l0_video + middlezone) - offset) * SECTORSIZE)) return 1;
    if ((buffer[0] != 0) || memcmp(buffer, buffer + 1, (((l0_video + middlezone) - offset) * SECTORSIZE) - 1)) {
      fprintf(stderr, "Error: Data found in Middle Zone A! Report this as soon as possible please!\n");
      return 1;
    }
    if (processblock(buffer, ((l0_video + middlezone) - offset) * SECTORSIZE)) return 1;
    sectorsdone += (l0_video + middlezone) - offset;
    offset += (l0_video + middlezone) - offset;
    printprogress(totalsize, sectorsdone);
  }
*/

  // Game Data
  while (offset < (l0_video + middlezone + gamedata)) {
    if ((nextgap = getnextgap(offset)) != 0) {
      // Game Data
      while ((offset + SECTORS) < nextgap) {
        if (readblock(buffer, offset, BUFFERSIZE)) return 1;
        if (processblock(buffer, BUFFERSIZE)) return 1;
        sectorsdone += SECTORS;
        offset += SECTORS;
        printprogress(totalsize, sectorsdone);
      }
      if (offset < nextgap) {
        if (readblock(buffer, offset, (nextgap - offset) * SECTORSIZE)) return 1;
        if (processblock(buffer, (nextgap - offset) * SECTORSIZE)) return 1;
        sectorsdone += (nextgap - offset);
        offset += (nextgap - offset);
        printprogress(totalsize, sectorsdone);
      }

      // Game Data Gap
      gapsize = getgapsize(nextgap);
      memset(buffer, 0, BUFFERSIZE);
      while ((offset + SECTORS) < (nextgap + gapsize)) {
        if (processblock(buffer, BUFFERSIZE)) return 1;
        sectorsdone += SECTORS;
        offset += SECTORS;
        printprogress(totalsize, sectorsdone);
      }
      if (offset < (nextgap + gapsize)) {
        if (processblock(buffer, ((nextgap + gapsize) - offset) * SECTORSIZE)) return 1;
        sectorsdone += ((nextgap + gapsize) - offset);
        offset += ((nextgap + gapsize) - offset);
        printprogress(totalsize, sectorsdone);
      }

      continue;
    }

    // Game Data End
    while ((offset + SECTORS) < (l0_video + middlezone + gamedata)) {
      if (readblock(buffer, offset, BUFFERSIZE)) return 1;
      if (processblock(buffer, BUFFERSIZE)) return 1;
      sectorsdone += SECTORS;
      offset += SECTORS;
      printprogress(totalsize, sectorsdone);
    }
    if (offset < (l0_video + middlezone + gamedata)) {
      if (readblock(buffer, offset, ((l0_video + middlezone + gamedata) - offset) * SECTORSIZE)) return 1;
      if (processblock(buffer, ((l0_video + middlezone + gamedata) - offset) * SECTORSIZE)) return 1;
      sectorsdone += ((l0_video + middlezone + gamedata) - offset);
      offset += ((l0_video + middlezone + gamedata) - offset);
      printprogress(totalsize, sectorsdone);
    }
  }

  // Middle Zone D
  offset = 0;
  memset(buffer, 0, BUFFERSIZE);
  while ((offset + SECTORS) < middlezone) {
    if (processblock(buffer, BUFFERSIZE)) return 1;
    sectorsdone += SECTORS;
    offset += SECTORS;
    printprogress(totalsize, sectorsdone);
  }
  if (offset < middlezone) {
    if (processblock(buffer, (middlezone - offset) * SECTORSIZE)) return 1;
    sectorsdone += (middlezone - offset);
    offset += (middlezone - offset);
    printprogress(totalsize, sectorsdone);
  }

  // L1 Video
  if (setlockingmode(MODE_LOCKED)) return 1;
  offset = l0_video;
  while ((offset + SECTORS) < (l0_video + l1_video)) {
    if (readblock(buffer, offset, BUFFERSIZE)) return 1;
    if (processblock(buffer, BUFFERSIZE)) return 1;
    sectorsdone += SECTORS;
    offset += SECTORS;
    printprogress(totalsize, sectorsdone);
  }
  if (offset < (l0_video + l1_video)) {
    if (readblock(buffer, offset, ((l0_video + l1_video) - offset) * SECTORSIZE)) return 1;
    if (processblock(buffer, ((l0_video + l1_video) - offset) * SECTORSIZE)) return 1;
    sectorsdone += (l0_video + l1_video) - offset;
    printprogress(totalsize, sectorsdone);
  }

  printf("\n\n");

  if (setlockingmode(MODE_WXRIPPER)) return 1;

  return 0;
}

unsigned int getnextgap(unsigned int offset) {
  int i;

  for (i = 0; i < sectorranges; i++) {
    if (securitysectors[i].start < offset) continue;
    return securitysectors[i].start;
  }

  return 0;
}

unsigned int getgapsize(unsigned int gap) {
  int i;

  for (i = 0; i < sectorranges; i++) {
    if (securitysectors[i].start == gap) return (securitysectors[i].end - securitysectors[i].start + 1);
  }

  return 0;
}

void printprogress(unsigned int totalsize, unsigned int sectorsdone) {
  static unsigned long long starttime = millisecondstime();
  static unsigned long long lastupdate = starttime;
  unsigned long long currenttime = millisecondstime();
  static unsigned int rate = 0;
  static unsigned int ratedivisor = 0;

  printf("%u (%u%%", sectorsdone, ((sectorsdone * 100) / totalsize));
  if (currenttime > (lastupdate + 2000)) {
    rate = ((sectorsdone / 512 * 100000) / (currenttime - starttime));
    ratedivisor = rate - ((rate / 100) * 100);
    rate /= 100;
    lastupdate = currenttime;
  }
  if (currenttime > (starttime + 2000)) {
    printf(", %u.%02u MB/sec", rate, ratedivisor);
  }
  printf(")   \r");
  fflush(stdout);
}

int setlockingmode(unsigned char mode) {
  unsigned char cdb[5] = {0xff, 0x08, 0x01, 0x11};
  unsigned char buffer[SECTORSIZE];
  unsigned int sense;

  cdb[4] = mode;
  if (sendcdb(cdb, 5, buffer, SECTORSIZE, 1, &sense)) {
    fprintf(stderr, "Error: LOCKING MODE failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for LOCKING MODE.\n");
    return 1;
  }

  return 0;
}

int getlayersizes(layersize_t *layers) {
  unsigned int totallength;
  unsigned int startsector;
  unsigned int endsector;
  unsigned int numberoflayers;
  unsigned char buffer[SECTORSIZE];
  unsigned int sense;

  if (sendcdb((const unsigned char []){0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 10, buffer, SECTORSIZE, 1, &sense)) {
    fprintf(stderr, "Error: READ CAPACITY failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for READ CAPACITY.\n");
    return 1;
  }
  totallength = ((buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + (buffer[3] << 0) + 1);

  if (sendcdb((const unsigned char []){0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00}, 12, buffer, SECTORSIZE, 1, &sense)) {
    fprintf(stderr, "Error: READ DISC STRUCTURE failed.\n");
    return 1;
  }
  if (sense) {
    fprintf(stderr, "Error: Sense failed for READ DISC STRUCTURE.\n");
    return 1;
  }
  numberoflayers = (((buffer[6] & 0x60) >> 5) + 1);
  startsector = ((buffer[9] << 16) + (buffer[10] << 8) + (buffer[11] << 0));
  endsector = ((buffer[17] << 16) + (buffer[18] << 8) + (buffer[19] << 0));

  if (numberoflayers == 1) {
    layers->l0 = totallength;
    layers->l1 = 0;
  } else {
    layers->l0 = (endsector - startsector) + 1;
    layers->l1 = (totallength - layers->l0);
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

int readblock(unsigned char *buffer, unsigned int offset, size_t size) {
  int retry;
  unsigned int sense = 0;
  unsigned char read10[10] = {0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char read12[12] = {0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00};

  retry = 0;
  read10[2] = (offset & 0xff000000) >> 24;
  read10[3] = (offset & 0x00ff0000) >> 16;
  read10[4] = (offset & 0x0000ff00) >> 8;
  read10[5] = (offset & 0x000000ff) >> 0;
  read10[7] = ((size / SECTORSIZE) & 0xff00) >> 8;
  read10[8] = ((size / SECTORSIZE) & 0x00ff) >> 0;
  do {
    if (sendcdb(read10, 10, buffer, size, 1, &sense)) {
      fprintf(stderr, "Error: MMC READ 10 failed.\n");
      return 1;
    }
    retry++;
  } while ((sense != 0) && (retry < 5));
  if (sense == 0) return 0;

  retry = 0;
  read12[2] = (offset & 0xff000000) >> 24;
  read12[3] = (offset & 0x00ff0000) >> 16;
  read12[4] = (offset & 0x0000ff00) >> 8;
  read12[5] = (offset & 0x000000ff) >> 0;
  read12[8] = ((size / SECTORSIZE) & 0xff00) >> 8;
  read12[9] = ((size / SECTORSIZE) & 0x00ff) >> 0;
  do {
    if (sendcdb(read12, 12, buffer, size, 1, &sense)) {
      fprintf(stderr, "Error: MMC READ 12 failed.\n");
      return 1;
    }
    retry++;
  } while ((sense != 0) && (retry < 5));
  if (sense == 0) return 0;

  fprintf(stderr, "Error: Sense error.\n");
  return 1;
}

int processblock(const unsigned char *buffer, size_t size) {
#ifndef __APPLE__
  crcutil->Compute(buffer, size, &crc);
#else
  CRC32_Update(&crc32context, buffer, size);
#endif
  MD5_Update(&md5context, buffer, size);
  SHA1_Update(&sha1context, buffer, size);

  if (fd && (write(fd, buffer, size) < (ssize_t)size)) {
    perror(outputfile);
    return 1;
  }

  return 0;
}
