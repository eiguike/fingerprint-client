#include <stdio.h>
#include <stdlib.h>

#include "server.h"

int main() {
  SERVER * Server = InitializeServer(8000);
  Server->Start(Server);
}
