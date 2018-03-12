#include <stdio.h>
#include <stdlib.h>

#include "device.h"
#include "fingerprint.h"

int
Device_Update (
    DEVICE* This
    )
{
  printf("Device_Update called\n");
  return 0;
}

int
Device_Verify (
    DEVICE* This
    )
{
  printf("Device_Verify called\n");
  return 0;
}

int
Device_Enroll (
    DEVICE* This
    )
{
  printf("Device_Enroll called\n");
  return 0;
}

void
Device_Dispose (
    DEVICE* This
    )
{
  if (This != NULL) {
    if (This->Fingerprint != NULL) {
      This->Fingerprint->Dispose(This->Fingerprint);
      This->Fingerprint = NULL;
    }
    free(This);
  }
}

DEVICE*
Device_Init (
    PROCESS_TYPE Type
    )
{
  DEVICE* Device = NULL;

  Device = calloc(1, sizeof(DEVICE));

  if (Device == NULL) {
    printf("Calloc returned NULL...\n");
    goto GENERAL_ERROR;
  }

  Device->Enroll = Device_Enroll;
  Device->Verify = Device_Verify;
  Device->Dispose = Device_Dispose;
  Device->Update = Device_Update;

  switch(Type) {
    case ENROLL_PROCESS:
    case VERIFY_PROCESS:
      Device->Fingerprint = Fingerprint_Init(Type);
      if (Device->Fingerprint == NULL) {
	goto GENERAL_ERROR;
      }
      break;
    default:
      printf("Unknown process, exiting...\n");
      goto GENERAL_ERROR;
  }

  goto FINISH;

GENERAL_ERROR:
  if (Device != NULL) {
    Device->Dispose(Device);
    Device = NULL;
  }

FINISH:
  return Device;
}

