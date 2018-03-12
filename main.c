#include <stdio.h>
#include <stdlib.h>

#include "server.h"
#include "device.h"
#include "fingerprint.h"

int main() {
  //SERVER * Server = InitializeServer(8000);
  //Server->Start(Server);
  DEVICE* Device = NULL;

#ifdef WIRINGPILIB
  // Initializing WiringPI
  printf("Initializing WiringPi...");
  wiringPiSetup();
  pinMode(DOOR, OUTPUT);
  digitalWrite(DOOR, LOW);
  printf("OK!\n");
#endif

  Device = Device_Initialize(VERIFY_PROCESS);
}
