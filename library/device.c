#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "device.h"
#include "fingerprint.h"

extern char* gUrl;
extern char* gPassword;

int
Device_SentRequest_Callback (
    char *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
    )
{
  printf("Device_SentRequest_Callback Begin\n");
  char*   Aux = NULL;
  DEVICE* This = NULL;

  if (userdata == NULL) {
    goto FINISH;
  }

  Aux = ptr;
  This = (DEVICE*)userdata;

  printf("ptr %s\n", Aux);

  if(strstr(Aux, "true") != NULL){
    printf("OUTDATED!!\n");
    This->Outdated = 1;
  }else{
    printf("UP TO DATE!\n");
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
  printf("Device_Verify Begin\n");

  if (This == NULL) {
    goto FINISH;
  }

  size_t CacheMatchPos = 0;
  int    ResultCode = 0;

  ResultCode = fp_identify_finger(This->Device, This->Fingerprint->FingerprintList, &CacheMatchPos);
  if (ResultCode < 0) {
    printf("ERROR MATCHING FINGERPRINT!!\n");
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

FINISH:
  printf("Device_Verify End\n");
  return ResultCode;
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
    if (This->Device != NULL) {
      free(This->Device);
      This->Device = NULL;
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
  printf("Device_InitLibFP Begin %d\n", __LINE__);

  struct fp_dscv_dev** DevicesFound = NULL;
  struct fp_dscv_dev*  DiscoverDevice = NULL;
  struct fp_driver*    Driver = NULL;
  struct fp_dev*       Device =  NULL;

  // if the lib couldn't be initialized
  if (fp_init() < 0) {
    printf("Failed to initialize libfprint!");
  }

  // find and open fingerprint reader
  DevicesFound = fp_discover_devs();

  // if no device found, exit the program
  if (DevicesFound == NULL || DevicesFound[0] == NULL) {
    printf("No reader found!");
  }

  // list devices found
  //cout << "Chosen reader: " << endl;
  for (int i = 0; DevicesFound[i] != NULL; i++) {
    DiscoverDevice = DevicesFound[i];
    Driver = fp_dscv_dev_get_driver(DiscoverDevice);
    printf("%s\n", fp_driver_get_full_name(Driver));
  }

  // choose the first reader to use, and open it
  Device = fp_dev_open(DevicesFound[0]);

  // check if the reader could be opened
  if (Device == NULL) {
    printf("Couldn't open selected reader for use!");
  } else {
    printf("❮ ✔ ❯ Reader ready\n");
  }

  // free list of devices from memory
  fp_dscv_devs_free(DevicesFound);

  This->Device = Device;
  printf("Device_InitLibFP End %d\n", __LINE__);
}

DEVICE*
Device_Init (
    PROCESS_TYPE Type
    )
{
  printf("Device_Init Begin %d\n", __LINE__);
  DEVICE* Device = NULL;

  Device = calloc(1, sizeof(DEVICE));

  if (Device == NULL) {
    printf("Calloc returned NULL...\n");
    goto GENERAL_ERROR;
  }

  Device->Enroll = Device_Enroll;
  Device->Verify = Device_Verify;
  Device->Dispose = Device_Dispose;

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

