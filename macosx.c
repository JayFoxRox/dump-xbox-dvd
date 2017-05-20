// Copyright 2017 Jannik Vogel
// Licensed under GPLv3 or any later version.
// Refer to the LICENSE.txt file included.

#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <CoreFoundation/CFString.h>
#include <IOKit/scsi/SCSITaskLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>

#include "platform.h"

int drive;
IOCFPlugInInterface **PlugIn;
MMCDeviceInterface **MMCDevice;
SCSITaskDeviceInterface **SCSITaskDevice;
SCSITaskInterface **SCSITask;

int getdrive(char *arg) {
  if (strlen(arg) < 13 || strlen(arg) > 15) return 1;
  if (strncmp("IODVDServices", arg, 13) != 0) return 1;
  if (strlen(arg) == 13) {
    drive = 0;
    return 0;
  }
  if (arg[13] != '/') return 1;
  if (arg[14] < '0' || arg[14] > '9') return 1;

  drive = arg[14] - '0';
  return 0;
}

int opendrive() {
  int i;
  SInt32 score;
  IOReturn result;
  io_iterator_t iterator;
  CFMutableDictionaryRef dict;
  io_object_t device;
  CFStringRef devicepathUTF8;
  char devicepath[256];
  char *unmountcommand;

  if ((dict = IOServiceMatching("IODVDServices")) == NULL) {
    printf("IOServiceMatching\n");
    return 1;
  }

  result = IOServiceGetMatchingServices(kIOMasterPortDefault, dict, &iterator);

  if ((result != kIOReturnSuccess) || (iterator == (io_iterator_t)0)) {
    printf("IOServiceGetMatchingServices\n");
    return 1;
  }

  for (i = 0; (device = IOIteratorNext(iterator)) != (io_iterator_t)0; i++) {
    if (drive == i) break;
  }

  IOObjectRelease(iterator);

  if (device == (io_object_t)0) {
    printf("IOIteratorNext\n");
    return 1;
  }

  if ((devicepathUTF8 = (CFStringRef)IORegistryEntrySearchCFProperty(device, kIOServicePlane, CFSTR(kIOBSDNameKey), kCFAllocatorDefault, kIORegistryIterateRecursively)) == NULL) {
    printf("IORegistryEntrySearchCFProperty\n");
    return 1;
  }

  if (CFStringGetCString(devicepathUTF8, devicepath, 256, kCFStringEncodingUTF8) == FALSE) {
    printf("CFStringGetCString\n");
    return 1;
  }
  
  if ((unmountcommand = (char *)malloc(strlen("/usr/sbin/diskutil unmountDisk > /dev/null") + strlen(devicepath) + 1)) == NULL) {
    printf("malloc\n");
    return 1;
  }

  sprintf(unmountcommand, "/usr/sbin/diskutil unmountDisk %s > /dev/null", devicepath);
  CFRelease(devicepathUTF8);
  
  if (system(unmountcommand) != 0) {
    free(unmountcommand);
    printf("system\n");
    return 1;
  }

  free(unmountcommand);

  score = 0;
  if ((result = IOCreatePlugInInterfaceForService(device, kIOMMCDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &PlugIn, &score)) != kIOReturnSuccess) {
    printf("IOCreatePlugInInterfaceForService\n");
    if ((result = IOCreatePlugInInterfaceForService(device, kIOSCSITaskDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &PlugIn, &score)) != kIOReturnSuccess) {
      printf("IOCreatePlugInInterfaceForService\n");
      return 1;
    }
    if ((*PlugIn)->QueryInterface(PlugIn, CFUUIDGetUUIDBytes(kIOSCSITaskDeviceInterfaceID), (void **)&MMCDevice) != KERN_SUCCESS) {
      printf("QueryInterface\n");
      return 1;
    }
  } else {
    if ((*PlugIn)->QueryInterface(PlugIn, CFUUIDGetUUIDBytes(kIOMMCDeviceInterfaceID), (void **)&MMCDevice) != KERN_SUCCESS) {
      printf("QueryInterface\n");
      return 1;
    }
  }

  if ((SCSITaskDevice = (*MMCDevice)->GetSCSITaskDeviceInterface(MMCDevice)) == NULL) {
    printf("GetSCSITaskDeviceInterface\n");
    return 1;
  }

  if ((*SCSITaskDevice)->ObtainExclusiveAccess(SCSITaskDevice) != kIOReturnSuccess) { 
    printf("ObtainExclusiveAccess\n");
    return 1;
  }

  if ((SCSITask = (*SCSITaskDevice)->CreateSCSITask(SCSITaskDevice)) == NULL) {
    printf("CreateSCSITask\n");
    return 1;
  }

  (*SCSITask)->SetTimeoutDuration(SCSITask, 10 * 1000);

  return 0;
}

void closedrive() {
  (*SCSITask)->Release(SCSITask);
  (*SCSITaskDevice)->ReleaseExclusiveAccess(SCSITaskDevice);
  (*SCSITaskDevice)->Release(SCSITaskDevice);
  (*MMCDevice)->Release(MMCDevice);
  IODestroyPlugInInterface(PlugIn);
}

unsigned long long millisecondstime() {
  struct timeval currenttime;
  time_t unixtime = time(NULL);
  gettimeofday(&currenttime, NULL);
  return ((unixtime * 1000) + (currenttime.tv_usec / 1000));
}

int sendcdb(const unsigned char *cdb, unsigned char cdblength, unsigned char *buffer, size_t size, int in, unsigned int *sense) {
  IOVirtualRange range;
  SCSI_Sense_Data sensedata;
  SCSITaskStatus status;

  if ((*SCSITask)->SetCommandDescriptorBlock(SCSITask, (unsigned char *)cdb, cdblength) != kIOReturnSuccess) {
    printf("SetCommandDescriptorBlock\n");
    *sense = 1;
    return 1;
  }

  range.address = (IOVirtualAddress)buffer;
  range.length = size;

  if ((*SCSITask)->SetScatterGatherEntries(SCSITask, &range, 1, size, (in ? kSCSIDataTransfer_FromInitiatorToTarget :  kSCSIDataTransfer_FromTargetToInitiator)) != kIOReturnSuccess) {
    printf("SetScatterGatherEntries\n");
    *sense = 1;
    return 1;
  }

  memset(&sensedata, 0, sizeof(SCSI_Sense_Data));

  if ((*SCSITask)->ExecuteTaskSync(SCSITask, &sensedata, &status, NULL) != kIOReturnSuccess) {
    printf("ExecuteTaskSync\n");
    *sense = 1;
    return 1;
  }

  *sense = ((((unsigned char *)&sensedata)[2] & 0x0f) << 16) + (((unsigned char *)&sensedata)[12] << 8) + ((unsigned char *)&sensedata)[13];
  return 0;
}
