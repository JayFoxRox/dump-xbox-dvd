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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <tchar.h>
#include <time.h>
#include <unistd.h>
#include <windows.h>

#include "interface.h"
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

#define SCSI_IOCTL_DATA_OUT 0
#define SCSI_IOCTL_DATA_IN 1
#define IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004D014
#define SENSE_BUFFER_LENGTH 32

typedef struct _SCSI_PASS_THROUGH_DIRECT {
  USHORT Length;
  UCHAR  ScsiStatus;
  UCHAR  PathId;
  UCHAR  TargetId;
  UCHAR  Lun;
  UCHAR  CdbLength;
  UCHAR  SenseInfoLength;
  UCHAR  DataIn;
  ULONG  DataTransferLength;
  ULONG  TimeOutValue;
  PVOID  DataBuffer;
  ULONG  SenseInfoOffset;
  UCHAR  Cdb[16];
} SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;

typedef struct _SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER {
  SCSI_PASS_THROUGH_DIRECT sptd;
  ULONG	Filler;
  UCHAR	ucSenseBuf[SENSE_BUFFER_LENGTH];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, *PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;
  
typedef struct {
  unsigned int start;
  unsigned int end;
} sectorrange_t;

typedef struct {
  size_t l0;
  size_t l1;
} layersize_t;

char drive;
HANDLE drivehandle;

const char *outputfile;
int fd;

sectorrange_t *securitysectors;
int sectorranges;

crcutil_interface::CRC *crcutil;
unsigned long long crc;

MD5_CTX md5context;
SHA1_CTX sha1context;

int readsectorfile(const char *);
HANDLE opendrivehandle();
int digesttostr(char *, const unsigned char *, size_t);
void usage();
int freecell();
void printprogress(unsigned int, unsigned int);
unsigned int getnextgap(unsigned int);
unsigned int getgapsize(unsigned int);
UINT64 millisecondstime();
int setlockingmode(unsigned char);
int getlayersizes(layersize_t *);
int setstreaming();
int readblock(unsigned char *, unsigned int, size_t);
int processblock(const unsigned char *, size_t);
int sendcdb(const unsigned char *, unsigned char, unsigned char *, size_t, int, unsigned int *);

int main(int argc, char *argv[]) {
  int option, nooutput, ret;
  const char *sectorfile;
  unsigned char md5digest[MD5_DIGEST_LENGTH];
  unsigned char sha1digest[SHA1_DIGEST_LENGTH];
  char md5hash[(MD5_DIGEST_LENGTH * 2) + 1];
  char sha1hash[(SHA1_DIGEST_LENGTH * 2) + 1];

  fd = 0;
  nooutput = 0;
  drive = 0;
  outputfile = NULL;
  sectorfile = NULL;
  
  while ((option = getopt(argc, argv, "no:h?")) != -1) {
    switch (option) {
      case 'n':
        if (outputfile) {
          fprintf(stderr, "FreeCell.exe: -n option can not be used together with -o\n");
          return 1;
        }
        nooutput = 1;
        break;
      case 'o':
        if (nooutput) {
          fprintf(stderr, "FreeCell.exe: -p option can not be used together with -n\n");
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
  
  do {
    if (strlen(argv[optind]) > 2) break;
    if (strlen(argv[optind]) == 2 && argv[optind][1] != ':') break;
    if (argv[optind][0] < 'A' || argv[optind][0] > 'z') break;
    if (argv[optind][0] > 'Z' && argv[optind][0] < 'a') break;
    drive = argv[optind][0];
    if (drive > 'Z') drive -= ('a' - 'A');
  } while (0);    

  if (!drive) {
    fprintf(stderr, "FreeCell.exe: %s does not look like a valid drive\n", argv[optind]);
    return 1;
  }
  optind++;

  if (argc <= optind + 1) {
    sectorfile = argv[optind];
  }

  if (!nooutput && outputfile == NULL) outputfile = OUTPUTFILE;
  if (sectorfile == NULL) sectorfile = SECTORFILE;

  if (readsectorfile(sectorfile)) return 1;

  if ((drivehandle = opendrivehandle()) == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "Could not open drive %c:.\n", drive);
    if (securitysectors != NULL) free(securitysectors);
    return 1;
  }

  if ((outputfile != NULL) && ((fd = open(outputfile, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) == -1)) {
    perror(outputfile);
    CloseHandle(drivehandle);
    if (securitysectors != NULL) free(securitysectors);
    return 1;
  }

  crcutil = crcutil_interface::CRC::Create(POLY, 0, 32, true, 0, 0, 0, 0, NULL);
  crc = 0;
  MD5_Init(&md5context);
  SHA1_Init(&sha1context);

  ret = freecell();

  if (!ret) {
    MD5_Final(md5digest, &md5context);
    SHA1_Final(sha1digest, &sha1context);

    digesttostr(md5hash, md5digest, MD5_DIGEST_LENGTH);
    digesttostr(sha1hash, sha1digest, SHA1_DIGEST_LENGTH);

    printf("CRC32: %08x\n", (unsigned int)crc);
    printf("MD5:   %s\n", md5hash);
    printf("SHA1:  %s\n", sha1hash);
  }

  crcutil->Delete();
  if (fd) close(fd);
  CloseHandle(drivehandle);
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

HANDLE opendrivehandle() {
  LPTSTR drivepath;

  if((drivepath = (LPTSTR)calloc(sizeof("\\\\.\\.:"), sizeof(TCHAR))) == NULL) {
    fprintf(stderr, "Drivepath calloc failed. Out of memory?\n");
    return INVALID_HANDLE_VALUE;
  }
  _stprintf(drivepath, _T("\\\\.\\%c:"), drive);
  return CreateFile(drivepath,
                     GENERIC_READ | GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                     NULL,
                     OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL,
                     NULL
                    );
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
  fprintf(stderr, "Usage: FreeCell <DRIVE> [-n|-o OUTPUTFILE] [SECTORFILE]\n");
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
  size_t l0_video, l1_video, middlezone, gamedata;
  layersize_t layers;
  unsigned int totalsize, offset, sectorsdone, nextgap, gapsize;
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
  printf("L0 Video Size: %d\n", l0_video);
  printf("L1 Video Size: %d\n", l1_video);
  printf("Middle Zone Size: %d\n", middlezone);
  printf("Game Data Size: %d\n", gamedata);
  printf("Total Size: %d\n", totalsize);
  printf("\n");
  printf("Real Layer Break: %d\n", l0_video + middlezone + (gamedata / 2));
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
  while ((offset + SECTORS) < (l0_video + middlezone)) {
    if (readblock(buffer, offset, BUFFERSIZE)) return 1;
    if ((buffer[0] != 0) || memcmp(buffer, buffer + 1, BUFFERSIZE - 1)) {
      fprintf(stderr, "Error: Data found in Middle Zone A! Report this as soon as possible please!\n");
      return 1;
    }
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
  static UINT64 starttime = millisecondstime();
  static UINT64 lastupdate = starttime;
  UINT64 currenttime = millisecondstime();
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

UINT64 millisecondstime() {
  SYSTEMTIME currenttime;
  time_t unixtime = time(NULL);
  GetSystemTime(&currenttime);
  return ((unixtime * 1000) + currenttime.wMilliseconds);
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
  crcutil->Compute(buffer, size, &crc);
  MD5_Update(&md5context, buffer, size);
  SHA1_Update(&sha1context, buffer, size);

  if (fd && (write(fd, buffer, size) < (ssize_t)size)) {
    perror(outputfile);
    return 1;
  }

  return 0;
}

int sendcdb(const unsigned char *cdb, unsigned char cdblength, unsigned char *buffer, size_t size, int in, unsigned int *sense) {
  SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdwb;
  long unsigned int returned;

  memset(&sptdwb, 0, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));
  memset(buffer, 0, size);

  sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
  sptdwb.sptd.CdbLength = cdblength;
  sptdwb.sptd.SenseInfoLength = sizeof(sptdwb.ucSenseBuf);
  sptdwb.sptd.DataIn = (in ? SCSI_IOCTL_DATA_IN : SCSI_IOCTL_DATA_OUT);
  sptdwb.sptd.DataTransferLength = size;
  sptdwb.sptd.TimeOutValue = 20;
  sptdwb.sptd.DataBuffer = buffer;
  sptdwb.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);

  memcpy(sptdwb.sptd.Cdb, cdb, cdblength);

  if (!DeviceIoControl(drivehandle,
                       IOCTL_SCSI_PASS_THROUGH_DIRECT,
                       &sptdwb,
                       sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
                       &sptdwb,
                       sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
                       &returned,
                       NULL
                      )) {
     *sense = 1;
     return 1;
  }

  *sense = ((sptdwb.ucSenseBuf[2] & 0x0f) << 16) + (sptdwb.ucSenseBuf[12] << 8) + sptdwb.ucSenseBuf[13];
  return 0;
}
