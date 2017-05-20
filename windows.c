// Copyright 2017 Jannik Vogel
// Licensed under GPLv3 or any later version.
// Refer to the LICENSE.txt file included.

#include <stddef.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <windows.h>

#include "platform.h"

#define SCSI_IOCTL_DATA_OUT 0
#define SCSI_IOCTL_DATA_IN 1
#define IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004D014
#define SENSE_BUFFER_LENGTH 32

typedef struct _SCSI_PASS_THROUGH_DIRECT {
  unsigned short Length;
  unsigned char  ScsiStatus;
  unsigned char  PathId;
  unsigned char  TargetId;
  unsigned char  Lun;
  unsigned char  CdbLength;
  unsigned char  SenseInfoLength;
  unsigned char  DataIn;
  unsigned long  DataTransferLength;
  unsigned long  TimeOutValue;
  void            *DataBuffer;
  unsigned long  SenseInfoOffset;
  unsigned char  Cdb[16];
} SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;

typedef struct _SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER {
  SCSI_PASS_THROUGH_DIRECT sptd;
  unsigned long  Filler;
  unsigned char  ucSenseBuf[SENSE_BUFFER_LENGTH];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, *PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;

char drive;
HANDLE drivehandle;

int getdrive(char *arg) {
  if (strlen(arg) > 2) return 1;
  if (strlen(arg) == 2 && arg[1] != ':') return 1;
  if (arg[0] < 'A' || arg[0] > 'z') return 1;
  if (arg[0] > 'Z' && arg[0] < 'a') return 1;

  drive = arg[0];
  if (drive > 'Z') drive -= ('a' - 'A');

  return 0;
}

int opendrive() {
  LPTSTR drivepath;

  if((drivepath = (LPTSTR)calloc(sizeof("\\\\.\\.:"), sizeof(TCHAR))) == NULL) {
    fprintf(stderr, "Drivepath calloc failed. Out of memory?\n");
    return 1;
  }
  _stprintf(drivepath, _T("\\\\.\\%c:"), drive);
  drivehandle = CreateFile(drivepath,
                     GENERIC_READ | GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                     NULL,
                     OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL,
                     NULL
                    );

  if (drivehandle == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "%s: Could not open drive %c:.\n", executable, drive);
    return 1;
  }

  return 0;
}

void closedrive() {
  CloseHandle(drivehandle);
}

unsigned long long millisecondstime() {
  SYSTEMTIME currenttime;
  time_t unixtime = time(NULL);
  GetSystemTime(&currenttime);
  return ((unixtime * 1000) + currenttime.wMilliseconds);
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
