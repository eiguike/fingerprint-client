#ifndef SERVER_H
#define SERVER_H

#include <libwebsockets.h>

#include "protocols/http_protocol.h"

#define EXAMPLE_RX_BUFFER_BYTES (50)

typedef struct WEBSOCKET_SERVER {
  struct lws_protocols * Protocols;
  struct lws_context_creation_info * ContextInfo;
  struct lws_context * Context;
  unsigned int NumbersOfProtocols;
  short int IsStop;

  int (*Start)(struct WEBSOCKET_SERVER * this);
  int (*Stop)(struct WEBSOCKET_SERVER * this);
} SERVER;

int Start (SERVER * this);
int Stop (SERVER * this);
SERVER * InitializeServer(int Port);
SERVER * InitializeServerSSL(int Port);

#endif
