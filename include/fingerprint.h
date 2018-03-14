#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <libfprint/fprint.h>

typedef struct _FINGERPRINT_FILE {
  int UserId;
  char Fingerprint[16068];
} FINGERPRINT_FILE;

typedef struct FINGERPRINT_OBJECT {
  // Basic methods to fullfill FINGERPRINT list
  int (*Add)(struct FINGERPRINT_OBJECT* This, int Index);
  int (*Remove)(struct FINGERPRINT_OBJECT* This, int Index);

  // Release all FINGERPRINT objects
  void (*Dispose)(struct FINGERPRINT_OBJECT* This);

  // This functions retrieves new fingerprint database from the server
  int (*Update) (struct FINGERPRINT_OBJECT* This);

  // This functions send the new fingerprint database to the server
  int (*Send) (struct FINGERPRINT_OBJECT* This);

  // This functions load from local database its fingerprints
  int (*Load) (struct FINGERPRINT_OBJECT* This);

  // Used to store JSON
  void* Data;

  // Fingerprints stored
  struct fp_print_data** FingerprintList;

  // UserIds store
  int* UserIdList;
} FINGERPRINT;

FINGERPRINT* Fingerprint_Init(int Type);

#endif
