#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <libfprint/fprint.h>

typedef struct _FINGERPRINT_FILE {
  int UserId;
  char Fingerprint[16068];
} FINGERPRINT_FILE;

typedef struct _FINGERPRINT_FILE_ENROLL {
  int UserId;
  struct fp_print_data* Fingerprint;
} FINGERPRINT_FILE_ENROLL;

typedef struct FINGERPRINT_OBJECT {
  // Basic methods to fullfill FINGERPRINT list
  int (*Add)(struct FINGERPRINT_OBJECT* This, FINGERPRINT_FILE_ENROLL* Data);
  int (*Remove)(struct FINGERPRINT_OBJECT* This, int Index);

  // Release all FINGERPRINT objects
  void (*Dispose)(struct FINGERPRINT_OBJECT* This);

  // This functions retrieves new fingerprint database from the server
  int (*Update) (struct FINGERPRINT_OBJECT* This);

  // This functions send the new fingerprint database to the server
  int (*Send) (struct FINGERPRINT_OBJECT* This, struct fp_print_data* Data, int* Update);

  // This functions load from local database its fingerprints
  int (*Load) (struct FINGERPRINT_OBJECT* This);

  // Used to store JSON
  size_t LargePacket;
  int    NumberOfPackets;
  void** Data;

  // Fingerprints stored
  struct fp_print_data** FingerprintList;
  unsigned int NumberOfFingerprints;

  // UserIds store
  int* UserIdList;
} FINGERPRINT;

FINGERPRINT* Fingerprint_Init(int Type);

#endif
