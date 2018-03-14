#include <stdio.h>
#include <stdlib.h>

#include "server.h"
#include "device.h"
#include "fingerprint.h"

DEVICE* gDevice = NULL;

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

int main() {
  //SERVER * Server = InitializeServer(8000);
  //Server->Start(Server);

#ifdef WIRINGPILIB
  // Initializing WiringPI
  printf("Initializing WiringPi...");
  wiringPiSetup();
  pinMode(DOOR, OUTPUT);
  digitalWrite(DOOR, LOW);
  printf("OK!\n");
#endif

  signal(SIGINT, SignalHandler);
  gDevice = Device_Init(VERIFY_PROCESS);

  if (gDevice == NULL) {
    printf("Something wrong happened...\n");
    goto FINISH;
  }

  while(1) {
    gDevice->Verify(gDevice);
    if (gDevice->Outdated == 1) {
      gDevice->Fingerprint->Update(gDevice->Fingerprint);
      //gDevice->Fingerprint->Load(gDevice->Fingerprint);
    }
  }
FINISH:
  return 0;
}
