#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "device.h"
#include "fingerprint.h"

extern char* gUrl;
extern char* gPassword;

#define NUMBER_OF_TRIES 5

int
Device_SentRequest_Callback (
    char *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
    )
{
  char*   Aux = NULL;
  DEVICE* This = NULL;

  if (userdata == NULL) {
    goto FINISH;
  }

  Aux = ptr;
  This = (DEVICE*)userdata;

  if(strstr(Aux, "true") != NULL){
    printf("❮ ⚠ ❯ Fingerprint Database Outdated!\n");
    This->Outdated = 1;
  }else{
    printf("❮ ✔ ❯ Fingerprint Database Up to Date!\n");
    This->Outdated = 0;
  }

FINISH:
  return size*nmemb;
}

int
Device_SentRequest (
    DEVICE* This,
    int     UserId
    )
{
  if (This == NULL) {
    goto FINISH;
  }

  CURL*    Curl = NULL;
  CURLcode Resource = 0;
  char*    LocalUrl = NULL;
  char*    Body = NULL;
  char*    AccessBody = "embedded_password=%s&user_id=%d";
  char*    AccessUrl = "/api/fingerprint/access";

  if (UserId != -1) {
    UserId = This->Fingerprint->UserIdList[UserId];
  }

  // log on server that the door was opened
  printf("❮ ⬆ ❯ uploading log...\n");

  Curl = curl_easy_init();
  if (Curl == NULL){
    printf("❮ ⚠ ❯ Couldn't get a Curl handler!\n");
  } else {
    Body = realloc(Body, strlen(AccessBody) + strlen(gPassword) + 4);
    sprintf(Body, AccessBody, gPassword, UserId);

    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    LocalUrl = realloc(LocalUrl, strlen(gUrl) + strlen(AccessUrl) + 1);
    sprintf(LocalUrl, "%s%s", gUrl, AccessUrl);

    curl_easy_setopt(Curl, CURLOPT_URL, LocalUrl);

    /* Now specify the POST data */
    curl_easy_setopt(Curl, CURLOPT_POSTFIELDS, Body);
    curl_easy_setopt(Curl, CURLOPT_WRITEFUNCTION, Device_SentRequest_Callback);
    curl_easy_setopt(Curl, CURLOPT_WRITEDATA, This);

    /* Perform the request, Resource will get the return code */
    Resource = curl_easy_perform(Curl);

    /* Check for errors */
    if (Resource != CURLE_OK) {
      printf("❮ ⚠ ❯ %s\n", gUrl);
      printf("❮ ⚠ ❯ Could not save log on the server! (%s)\n", curl_easy_strerror(Resource));
    }else{
      printf("❮ ✔ ❯ Log saved to the server\n");
    }

    /* always cleanup */
    curl_easy_cleanup(Curl);
  }

FINISH:
  if (Body != NULL) {
    free(Body);
  }
  if (LocalUrl != NULL) {
    free(LocalUrl);
  }
  return Resource;
}


int
Device_Verify (
    DEVICE* This
    )
{
  if (This == NULL) {
    goto FINISH;
  }

  size_t         CacheMatchPos = 0;
  int            ResultCode = 0;
  struct fp_img* FingerprintImage = NULL;

  ResultCode = fp_identify_finger_img ( This->Device,
                                        This->Fingerprint->FingerprintList,
                                        &CacheMatchPos,
                                        &FingerprintImage );
  if (ResultCode < 0) {
    //printf("ERROR MATCHING FINGERPRINT!!\n");
  }

  switch (ResultCode){
    case FP_VERIFY_NO_MATCH:
      printf("❮ ☝ ✖ ❯ Fingerprint does not match any database entry\n");
      Device_SentRequest(This, -1);
      break;

    case FP_VERIFY_RETRY:
    case FP_VERIFY_RETRY_TOO_SHORT:
    case FP_VERIFY_RETRY_CENTER_FINGER:
    case FP_VERIFY_RETRY_REMOVE_FINGER:
      printf("❮ ☝ ↻ ❯ Failed to read fingerprint, retrying...\n");
      break;
    case FP_VERIFY_MATCH:
      printf("❮ ☝ ✔ ❯ Fingerprint match user ID:\n");
#ifdef WIRINGPILIB
      // open the door
      digitalWrite(DOOR, HIGH);
      delay(500);
      digitalWrite(DOOR, LOW);
#endif
      Device_SentRequest(This, CacheMatchPos);
      break;
  }

  if (FingerprintImage != NULL) {
    fp_img_standardize(FingerprintImage);
    fp_img_save_to_file(FingerprintImage, "finger_standardized.pgm");
  }

  if (This->FingerprintImage != NULL) {
    fp_img_free(This->FingerprintImage);
  }
  This->FingerprintImage = FingerprintImage;

FINISH:
  return ResultCode;
}


int
Device_EnrollTest (
    DEVICE* This,
    int     Signature
    )
{
  if (This == NULL) {
    goto FINISH;
  }

  size_t CacheMatchPos = 0;
  int    ResultCode = 0;

  ResultCode = fp_identify_finger_img ( This->Device,
                                        This->Fingerprint->FingerprintList,
                                        &CacheMatchPos,
                                        NULL );
  if (ResultCode < 0) {
  }

  switch (ResultCode){
    case FP_VERIFY_NO_MATCH:
      printf("❮ ☝ ✖ ❯ Fingerprint does not match any database entry\n");
      break;

    case FP_VERIFY_RETRY:
    case FP_VERIFY_RETRY_TOO_SHORT:
    case FP_VERIFY_RETRY_CENTER_FINGER:
    case FP_VERIFY_RETRY_REMOVE_FINGER:
      printf("❮ ☝ ↻ ❯ Failed to read fingerprint, retrying...\n");
      break;
    case FP_VERIFY_MATCH:
      if (This->Fingerprint->UserIdList[CacheMatchPos] == Signature) {
        printf("❮ ☝ ✔ ❯ Fingerprint match user\n");
        ResultCode = 0;
      } else {
        printf("❮ ☝ ↻ ❯ Failed to read fingerprint, retrying...\n");
        ResultCode = 1;
      }
      break;
  }

FINISH:
  return ResultCode;
}

int
Device_EnrollScan (
    DEVICE* This,
    FINGERPRINT_FILE_ENROLL* Data
    )
{

  int NumbersEnroll = 0;
  int Index = 0;
  int ResultCode = 0;
  struct fp_print_data* Fingerprint = NULL;

  NumbersEnroll = fp_dev_get_nr_enroll_stages(This->Device);

  for (Index = 0; Index < NumbersEnroll; Index++) {
    ResultCode = fp_enroll_finger(This->Device, &Fingerprint);

    if (ResultCode < 0) {
      printf("❮ ⚠ ❯ I/0 Error, aborting enrollment...\n");
      goto FINISH;
    }

    switch(ResultCode) {
      case FP_ENROLL_FAIL:
        printf("❮ ☝ ✖ ❯ Data processing failed, aborting enrollment ...\n");
        goto FINISH;
      case FP_ENROLL_RETRY:
      case FP_ENROLL_RETRY_TOO_SHORT:
      case FP_ENROLL_RETRY_CENTER_FINGER:
      case FP_ENROLL_RETRY_REMOVE_FINGER:
        printf("❮ ☝ ↻ ❯ Failed to read fingerprint, retrying stage...\n");
        Index--;
        continue;
      case FP_ENROLL_PASS:
        printf("❮ ☝ ✔ ❯ Stage %d/%d\n", 1 + Index, NumbersEnroll);
        break;
      case FP_ENROLL_COMPLETE:
        ResultCode = 0;
        printf("❮ ✔ ❯ Enrollment completed\n");
        break;
    }
  }
  Data->Fingerprint = Fingerprint;
  Data->UserId = -1;

FINISH:
  return ResultCode;
}

int
Device_Enroll (
    DEVICE* This
    )
{
  FINGERPRINT_FILE_ENROLL Data = { 0 };
  int Index = 0;
  int Score = 0;
  int ResultCode = 0;

  do {
    if (This->Fingerprint != NULL) {
      This->Fingerprint->Dispose(This->Fingerprint);
    }
    This->Fingerprint = Fingerprint_Init(ENROLL_PROCESS);

    if (Data.Fingerprint != NULL) {
      Data.Fingerprint = NULL;
    }

    ResultCode = Device_EnrollScan(This, &Data);
    if(ResultCode < 0) {
      goto FINISH;
    }

    // Successfull enroll, loading other fingerprints to test
    This->Fingerprint->Update(This->Fingerprint);
    if (This->Fingerprint->Load(This->Fingerprint) == 0) {
      //printf("Loading from file and adding...\n");
      This->Fingerprint->Add(This->Fingerprint, &Data);
    } else {
      //printf("Loading directly...\n");
      // not possible to load from file, set new fingerprint list
      This->Fingerprint->NumberOfFingerprints = 1;
      This->Fingerprint->FingerprintList = &(Data.Fingerprint);
      This->Fingerprint->UserIdList = &(Data.UserId);
    }

    for (Index = 0; Index < NUMBER_OF_TRIES; Index++) {
      ResultCode = Device_EnrollTest(This, Data.UserId);
      if(ResultCode < 0) {
        goto FINISH;
      } else if (ResultCode == 0) {
        Score++;
      }
      printf("SCORE: %d/%d\n", Score, NUMBER_OF_TRIES);
    }

  } while(Score < NUMBER_OF_TRIES - 1);

  This->Fingerprint->Send(This->Fingerprint,
                          Data.Fingerprint,
                          &(This->Outdated));

FINISH:

  if (ResultCode < 0) {
    if (Data.Fingerprint != NULL) {
      fp_print_data_free(Data.Fingerprint);
    }
    if (This->Fingerprint->FingerprintList != NULL) {
      //fp_print_data_free(This->Fingerprint->FingerprintList);
      This->Fingerprint->FingerprintList = NULL;
    }
    if (This->Fingerprint->UserIdList != NULL) {
      free(This->Fingerprint->UserIdList);
      This->Fingerprint->UserIdList = NULL;
    }
  }
  return ResultCode;
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
    if (This->FingerprintImage != NULL) {
      fp_img_free(This->FingerprintImage);
    }
    if (This->Device != NULL) {
      fp_dev_close(This->Device);
      fp_exit();
    }
    free(This);
  }
}

// TODO: REFACTOR THIS FUNCTION
void
Device_InitLibFP (
    DEVICE* This
    )
{
  struct fp_dscv_dev** DevicesFound = NULL;
  struct fp_dscv_dev*  DiscoverDevice = NULL;
  struct fp_driver*    Driver = NULL;
  struct fp_dev*       Device =  NULL;

  // if the lib couldn't be initialized
  if (fp_init() < 0) {
    printf("❮ ⚠ ❯ Failed to initialize Libfprint!");
  }

  // find and open fingerprint reader
  DevicesFound = fp_discover_devs();

  // if no device found, exit the program
  if (DevicesFound == NULL || DevicesFound[0] == NULL) {
    printf("❮ ⚠ ❯ No reader found!\n");
    goto FINISH;
  }

  // list devices found
  //cout << "Chosen reader: " << endl;
  for (int i = 0; DevicesFound[i] != NULL; i++) {
    DiscoverDevice = DevicesFound[i];
    Driver = fp_dscv_dev_get_driver(DiscoverDevice);
    printf("Reader choosen: %s\n", fp_driver_get_full_name(Driver));
  }

  // choose the first reader to use, and open it
  if (DevicesFound[0] != NULL) {
    Device = fp_dev_open(DevicesFound[0]);
  }

  // check if the reader could be opened
  if (Device == NULL) {
    printf("❮ ⚠ ❯ Couldn't open selected reader for use!\n");
  } else {
    printf("❮ ✔ ❯ Reader ready\n");
  }

  // free list of devices from memory
  if (DevicesFound != NULL) {
    fp_dscv_devs_free(DevicesFound);
  }

  This->Device = Device;
FINISH:
  return;
}

DEVICE*
Device_Init (
    PROCESS_TYPE Type
    )
{
  DEVICE* Device = NULL;

  Device = calloc(1, sizeof(DEVICE));

  if (Device == NULL) {
    goto GENERAL_ERROR;
  }

  Device->Enroll = Device_Enroll;
  Device->Verify = Device_Verify;
  Device->Dispose = Device_Dispose;

  switch(Type) {
    case ENROLL_PROCESS:
      break;
    case VERIFY_PROCESS:
      Device->Fingerprint = Fingerprint_Init(Type);
      if (Device->Fingerprint == NULL) {
        goto GENERAL_ERROR;
      }
      break;
    default:
      goto GENERAL_ERROR;
  }

#ifdef WIRINGPILIB
  // Initializing WiringPI
  printf("Initializing WiringPi...");
  wiringPiSetup();
  pinMode(DOOR, OUTPUT);
  digitalWrite(DOOR, LOW);
  printf("OK!\n");
#endif

  Device_InitLibFP(Device);
  if(Device->Device == NULL) {
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

