#ifndef DEVICE_H
#define DEVICE_H

#include <libfprint/fprint.h>
#include "fingerprint.h"

typedef enum {
  ENROLL_PROCESS,
  VERIFY_PROCESS
} PROCESS_TYPE;

typedef struct FINGERPRINT_DEVICE {
  // List of fingerprints
  FINGERPRINT* Fingerprint;

  // This functions register a new fingerprint
  int (*Enroll) (struct FINGERPRINT_DEVICE* This);

  // This functions verifies if there is a match in database with the fingerprint
  int (*Verify) (struct FINGERPRINT_DEVICE* This);

  // Releases DEVICE data structure
  void (*Dispose) (struct FINGERPRINT_DEVICE* This);

  // Boolean to check if this DEVICE should update its fingerprints
  int Outdated;

  struct fp_dev* Device;
} DEVICE;

DEVICE* Device_Init(PROCESS_TYPE Type);

#endif
