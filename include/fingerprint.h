#ifndef FINGERPRINT_H
#define FINGERPRINT_H

typedef struct FINGERPRINT_OBJECT {

  // Basic methods to fullfill FINGERPRINT list
  int (*Add)(struct FINGERPRINT_OBJECT* This);
  int (*Remove)(struct FINGERPRINT_OBJECT* This);

  // Release all FINGERPRINT objects
  int (*Dispose)(struct FINGERPRINT_OBJECT* This);

  // This functions retrieves new fingerprint database from the server
  int (*Update) (struct FINGERPRINT_DEVICE* This);

  // This functions send the new fingerprint database to the server
  int (*Send) (struct FINGERPRINT_DEVICE* This);
} FINGERPRINT;

FINGERPRINT* Fingerprint_Init(PROCESS_TYPE Type);
FINGERPRINT* Fingerprint_LoadFromFile(char* FileName);

#endif
