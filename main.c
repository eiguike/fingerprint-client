#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <curl/curl.h>

#include "server.h"
#include "device.h"
#include "fingerprint.h"

DEVICE* gDevice = NULL;
SERVER* gServer = NULL;

char* gUrl = "http://localhost:3000";
char* gPassword = "testelabpesquisa";

void
SignalHandler(
    int Signal
    )
{
  printf("Exiting...\n");
  if (gDevice != NULL) {
    gDevice->Dispose(gDevice);
  }

  exit(0);
}

void*
WebServiceThread (
    void* Value
    )
{
  printf("WebServiceThread Begin\n");

  PROCESS_TYPE Type = *(PROCESS_TYPE*) Value;

  gServer = InitializeServer(8000);
  if (gServer != NULL) {
    gServer->Start(gServer);
  }

  printf("WebServiceThread End\n");
  return NULL;
}

void*
DeviceFingerprintThread (
    void* Value
    )
{
  PROCESS_TYPE Type = *(PROCESS_TYPE*) Value;
  printf("DeviceFingerprintThread Begin\n");
  gDevice = Device_Init(Type);

  if (gDevice == NULL) {
    printf("Something wrong happened...\n");
    goto FINISH;
  }

  switch(Type) {
    case ENROLL_PROCESS:
      while(1) {
        gDevice->Enroll(gDevice);
      }
      break;
    case VERIFY_PROCESS:
      while(1) {
        gDevice->Verify(gDevice);
        if (gDevice->Outdated == 1) {
          gDevice->Fingerprint->Update(gDevice->Fingerprint);
          gDevice->Fingerprint->Load(gDevice->Fingerprint);
        }
      }
      break;
  }

FINISH:
  printf("DeviceFingerprintThread End\n");
  return NULL;
}

int main() {
  //signal(SIGINT, SignalHandler);
  //PROCESS_TYPE Type = ENROLL_PROCESS;
  PROCESS_TYPE Type = VERIFY_PROCESS;

  printf ("Initializing libcurl... ");
  if (curl_global_init(CURL_GLOBAL_ALL) < 0) {
    printf("FAILED!\n");
    goto FINISH;
  }
  printf ("OK!\n");

  gDevice = Device_Init(Type);
  gDevice->Dispose(gDevice);
  //DeviceFingerprintThread((void*)&Type);
  //pthread_t WebService;
  //pthread_t DeviceFingerprint;

  //pthread_create(&WebService, NULL, WebServiceThread, (void*)&Type);
  //pthread_create(&DeviceFingerprint, NULL, DeviceFingerprintThread, (void*)&Type);

  //pthread_join(WebService, NULL);
  //pthread_join(DeviceFingerprint, NULL);
  //
  curl_global_cleanup();
FINISH:
  return 0;
}
