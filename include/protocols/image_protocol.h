#ifndef IMAGE_PROTOCOL_H
#define IMAGE_PROTOCOL_H
#include <stdio.h>
#include <stdlib.h>

#include "libwebsockets.h"
#include "libfprint/fprint.h"

typedef struct {
  char Preload[LWS_SEND_BUFFER_PRE_PADDING];
  struct fp_img* FingerprintImage;
} IMAGE_PROTOCOL_SESSION;

int
CallbackImage(
    struct lws *wsi,
    enum lws_callback_reasons reason,
    void *user,
    void *in,
    size_t len
    );

#endif
