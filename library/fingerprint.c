#include <stdio.h>
#include <stdlib.h>

#include "fingerprint.h"

int
Fingerprint_Update (
    FINGERPRINT* This
    )
{
  int Status = 0;

  if (This == NULL) {
    Status = 1;
    goto FINISH;
  }

  CURL* Curl = NULL;
  CURLcode Resource;

  Curl = curl_easy_init();

  if (Curl == NULL) {
    printf("Couldn't get a curl handler!!\n");
    Status = 1;
    goto FINISH;
  } else {
    
  }

FINISH:
  return Status;
}


FINGERPRINT*
Fingerprint_Init (
    PROCESS_TYPE Type
    )
{
  FINGERPRINT* Fingerprint = NULL;

  Fingerprint = calloc(1, sizeof(FINGERPRINT));

  if (Fingerprint == NULL) {
    printf("Calloc returned NULL...\n");
    goto FINISH;
  }

  Fingerprint->Add = Fingerprint_Add;
  Fingerprint->Remove = Fingerprint_Remove;
  Fingerprint->Dispose = Fingerprint_Dispose;

  printf ("Initializing libcurl... ");
  if (curl_global_init(CURL_GLOBAL_ALL) < 0) {
    printf("FAILED!\n");
    goto FINISH;
  }
  printf ("OK!\n");


  switch(Type) {
    case ENROLL_PROCESS:
      // Here we would like to create new fingerprints
      break;
    case VERIFY_PROCESS:
      // Here we would like to download from the database these fingerprints
      Fingerprint->Update(Fingerprint);
      break;
    default:
      printf("Unknown process, exiting...\n");
      Fingerprint->Dispose(Fingerprint);
      Fingerprint = NULL;
      break;
  }

FINISH:
  return Fingerprint;
}

