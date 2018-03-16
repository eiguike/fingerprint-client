#include "server.h"

int
CallbackImage(
    struct lws *wsi,
    enum lws_callback_reasons reason,
    void *user,
    void *in,
    size_t len
    )
{
  switch(reason) {
    case LWS_CALLBACK_ESTABLISHED:
      break;
    case LWS_CALLBACK_CLOSED:
      break;
    case LWS_CALLBACK_PROTOCOL_INIT:
      break;
    case LWS_CALLBACK_RECEIVE:
      break;
    case LWS_CALLBACK_SERVER_WRITEABLE:
      break;
    default:
      break;
  }

FINISH:
  return 0;
}
