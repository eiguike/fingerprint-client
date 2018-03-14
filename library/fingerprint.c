#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <curl/curl.h>

#include <libfprint/fprint.h>
#include <cjson/cJSON.h>

#include "fingerprint.h"
#include "device.h"

extern char* gUrl;
extern char* gPassword;

char* Url = "http://localhost:3000/api/fingerprint/";
char* Body = "embedded_password=testelabpesquisa";

unsigned char*
DecodeBinaryToB64 (
    struct fp_print_data** Print,
    size_t* Size
    )
{
  unsigned char* FingerprintData = NULL;
  unsigned char* Buffer = NULL;
  size_t         FingerprintDataSize = 0;
  BIO*           Bio = NULL;
  BIO*           Base64 = NULL;
  BUF_MEM*       BufferPtr;

  if (Print == NULL) {
    goto FINISH;
  }

  FingerprintDataSize = fp_print_data_get_data(*Print, &FingerprintData);

  if (FingerprintDataSize == 0) {
    goto FINISH;
  }

  Base64 = BIO_new(BIO_f_base64());
  Bio = BIO_new(BIO_s_mem());
  Bio = BIO_push(Base64, Bio);

  BIO_set_flags(Bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  BIO_write(Bio, FingerprintData, FingerprintDataSize);
  BIO_flush(Bio);
  BIO_get_mem_ptr(Bio, &BufferPtr);
  BIO_set_close(Bio, BIO_NOCLOSE);
  BIO_free_all(Bio);

  Buffer = (unsigned char*)calloc(FingerprintDataSize, sizeof(unsigned char));

  Bio = BIO_new_mem_buf(BufferPtr->data, -1);
  Base64 = BIO_new(BIO_f_base64());
  Bio = BIO_push(Base64, Bio);

  BIO_set_flags(Bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
  *Size = BIO_read(Bio, Buffer, BufferPtr->length);

  BIO_free_all(Bio);
  free(FingerprintData);

  if(fp_print_data_from_data(Buffer, FingerprintDataSize) == NULL){
    free(Buffer);
    Buffer = NULL;
  }

  free(BufferPtr);

FINISH:
  return Buffer;
}

unsigned char*
DecodeB64ToBinary (
    char* Data,
    size_t Size,
    size_t* DecodeLen
    )
{
  BIO*           Bio = NULL;
  BIO*           Base64 = NULL;
  unsigned char* Buffer = NULL;

  if (Data == NULL || DecodeLen == NULL) {
    goto FINISH;
  }

  // Converting Base64 to Binary
  *DecodeLen = (3*Size)/4;

  if (Data[Size - 1] == '=') {
    *DecodeLen -= 1;
  }
  if (Data[Size - 2] == '=') {
    *DecodeLen -= 1;
  }

  printf("SIZE %ld\n", Size);
  printf("DECODELEN %ld\n", *DecodeLen);

  Buffer = (unsigned char*) calloc(*DecodeLen + 1, sizeof(char));

  if (Buffer == NULL) {
    printf("calloc failed! %d\n", __LINE__);
    goto FINISH;
  }

  Bio = BIO_new_mem_buf(Data, Size);
  Base64 = BIO_new(BIO_f_base64());
  Bio = BIO_push(Base64, Bio);
  BIO_set_flags(Bio, BIO_FLAGS_BASE64_NO_NL);
  size_t Length = BIO_read(Bio, Buffer, Size - 1);
  BIO_free_all(Bio);

  if (Length == 0) {
    free(Buffer);
    Buffer = NULL;
  }


FINISH:
  return Buffer;
}

int
Fingerprint_Load (
    FINGERPRINT* This
    )
{
  printf("Fingerprint_Load Begin \n");

  FINGERPRINT_FILE       FingerprintInstance;
  FILE*                  File = NULL;
  struct fp_print_data** Fingerprints = NULL;
  int*                   UserIds = NULL;
  int                    NoFingerprints = 0;
  size_t                 DecodeLen = 0;
  unsigned char*         Buffer = NULL;
  int                    Status = 0;

  if (This == NULL) {
    goto FINISH;
  }

  File = fopen("sigla_database.db", "rb");

  if (File == NULL) {
    printf("fopen returned NULL %d\n", __LINE__);
    Status = 1;
    goto FINISH;
  }

  while(fscanf(File, "%d|%[^\n]", &FingerprintInstance.UserId, FingerprintInstance.Fingerprint) != EOF) {
  //while(fread(&FingerprintInstance, 1, sizeof(FINGERPRINT_FILE), File)) {
    NoFingerprints++;

    Fingerprints = realloc(Fingerprints, sizeof(struct fp_print_data*) * NoFingerprints);
    if (Fingerprints == NULL) {
      Status = 1;
      goto GENERAL_ERROR;
    }

    UserIds = realloc(UserIds, sizeof(int) * NoFingerprints);
    if (UserIds == NULL) {
      Status = 1;
      goto GENERAL_ERROR;
    }

    Buffer = DecodeB64ToBinary(FingerprintInstance.Fingerprint, 16068, &DecodeLen);

    if (Buffer == NULL) {
      Status = 1;
      goto GENERAL_ERROR;
    }

    Fingerprints[NoFingerprints - 1] = fp_print_data_from_data(Buffer, DecodeLen);
    UserIds[NoFingerprints - 1] = FingerprintInstance.UserId;

    if (Fingerprints[NoFingerprints - 1 ] == NULL ) {
      printf("could not ready entry from cache file\n");
      Status = 1;
      goto GENERAL_ERROR;
    }
  }

  // Last fingerprint should be NULL
  NoFingerprints++;
  Fingerprints = realloc(Fingerprints, sizeof(struct fp_print_data*) * NoFingerprints);
  if (Fingerprints == NULL) {
    Status = 1;
    goto GENERAL_ERROR;
  }

  Fingerprints[NoFingerprints - 1] = NULL;
  This->FingerprintList = Fingerprints;
  This->UserIdList = UserIds;
  goto FINISH;

GENERAL_ERROR:
  if (Fingerprints != NULL) {
    free(Fingerprints);
    Fingerprints = NULL;
  }
  if (UserIds != NULL) {
    free(UserIds);
    UserIds = NULL;
  }
  if (Buffer != NULL) {
    free(Buffer);
    Buffer = NULL;
  }

FINISH:
  return Status;
}

void
Fingerprint_Write (
    FINGERPRINT* This
    )
{
  printf("Fingerprint_Write Begin \n");
  FINGERPRINT_FILE FingerprintInstance = { 0 };
  cJSON*           JsonData = NULL;
  cJSON*           JsonInstance = NULL;
  cJSON*           UserId = NULL;
  cJSON*           Fingerprint = NULL;
  FILE*            File = NULL;

  if (This == NULL) {
    goto FINISH;
  }

  File = fopen("sigla_database.db", "w");

  if (File == NULL) {
    printf("fopen returned NULL\n");
    goto FINISH;
  }

  JsonData = cJSON_Parse((char*)This->Data);
  if (JsonData == NULL) {
    printf("Could not parse JSON request!\n");
    goto FINISH;
  } else {
    cJSON_ArrayForEach(JsonInstance, JsonData) {
      UserId = cJSON_GetObjectItemCaseSensitive(JsonInstance, "user_id");
      Fingerprint = cJSON_GetObjectItemCaseSensitive(JsonInstance, "biometric");

      FingerprintInstance.UserId = UserId->valueint;
      strcpy(FingerprintInstance.Fingerprint, Fingerprint->valuestring);

      //printf("USERID: %d\n", FingerprintInstance.UserId);
      //printf("FINGERPRINT: %s\n", FingerprintInstance.Fingerprint);

      //fwrite (&FingerprintInstance, sizeof(FINGERPRINT_FILE), 1, File);
      fprintf(File, "%d|%s\n", UserId->valueint, Fingerprint->valuestring);
    }
  }

FINISH:
  if (File != NULL) {
    fclose(File);
  }

  if (JsonData != NULL) {
    cJSON_Delete(JsonData);
  }
  return;
}

void
Fingerprint_Dispose (
    FINGERPRINT* This
    )
{
  printf("Fingerprint_Dispose Begin\n");
  if (This != NULL) {
    if (This->Data != NULL) {
      free(This->Data);
    }
    if (This->FingerprintList != NULL) {
      free(This->FingerprintList);
    }
    if (This->UserIdList != NULL) {
      free(This->UserIdList);
    }
    free(This);
  }
  return;
}

int
Fingerprint_Download (
    char *ptr,
    size_t size,
    size_t nmemb,
    void *userdata
    )
{
  FINGERPRINT* This = NULL;
  char*        Aux = NULL;
  int          SizeOldData = 0;
  int          NewSize = 0;

  if (userdata == NULL) {
    goto FINISH;
  }

  This = (FINGERPRINT*) userdata;
  Aux = (char*) This->Data;

  if (Aux != NULL) {
    SizeOldData = strlen(Aux);
  }

  if (strlen(ptr) != nmemb) {
    // it is the last packet, so we need to remove some chunk bytes there
    Aux = (char*) realloc(Aux, strlen(ptr) - 7 + SizeOldData + 1);
    memcpy(Aux + SizeOldData, ptr, strlen(ptr) - 7);
    //strncpy(Aux + SizeOldData, ptr, strlen(ptr) - 7);
    NewSize = strlen(ptr) - 7 + SizeOldData;
  } else {
    Aux = (char*) realloc(Aux, strlen(ptr) + SizeOldData + 1);
    //strncpy(Aux + SizeOldData, ptr, strlen(ptr));
    memcpy(Aux + SizeOldData, ptr, strlen(ptr));
    NewSize = strlen(ptr) + SizeOldData;
  }

  This->Data = Aux;

FINISH:
  return size * nmemb;
}

int
Fingerprint_Add (
    FINGERPRINT* This,
    int Index
    )
{
  return 0;
}

int
Fingerprint_Remove (
    FINGERPRINT* This,
    int Index
    )
{
  return 0;
}


int
Fingerprint_Update (
    FINGERPRINT* This
    )
{
  printf("Fingerprint_Update Begin\n");
  int       Status = 0;
  CURL*     Curl = NULL;
  CURLcode  Resource;

  if (This == NULL) {
    Status = 1;
    goto FINISH;
  }

  Curl = curl_easy_init();

  if (Curl == NULL) {
    printf("Couldn't get a curl handler!!\n");
    Status = 1;
    goto FINISH;
  } else {
    curl_easy_setopt(Curl, CURLOPT_URL, Url);

    // Specify the POST Data
    curl_easy_setopt(Curl, CURLOPT_POSTFIELDS, Body);
    curl_easy_setopt(Curl, CURLOPT_WRITEFUNCTION, Fingerprint_Download);
    curl_easy_setopt(Curl, CURLOPT_WRITEDATA, This);

    Resource = curl_easy_perform(Curl);

    if (Resource != CURLE_OK) {
      printf("Could not download all fingerprints!! %s\n", curl_easy_strerror(Resource));
      Status = 1;
      goto FINISH;
    }
  }

  Fingerprint_Write (This);

FINISH:
  if (Curl != NULL) {
    curl_easy_cleanup(Curl);
    Curl = NULL;
  }
  if (This->Data != NULL) {
    free(This->Data);
    This->Data = NULL;
  }

  return Status;
}

FINGERPRINT*
Fingerprint_Init (
    int Type
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
  Fingerprint->Update = Fingerprint_Update;
  Fingerprint->Dispose = Fingerprint_Dispose;
  Fingerprint->Load = Fingerprint_Load;

  printf ("Initializing libcurl... ");
  if (curl_global_init(CURL_GLOBAL_ALL) < 0) {
    printf("FAILED!\n");
    goto GENERAL_ERROR;
  }
  printf ("OK!\n");

  switch(Type) {
    case ENROLL_PROCESS:
      // Here we would like to create new fingerprints
      break;
    case VERIFY_PROCESS:
      // Here we would like to download from the database these fingerprints
      if (Fingerprint->Update(Fingerprint) != 0) {
        printf("Something wrong happened in Update\n");
      }

      if (Fingerprint->Load(Fingerprint) != 0) {
        printf("Something wrong happened in Load function\n");
        goto GENERAL_ERROR;
      }
      break;
    default:
      printf("Unknown process, exiting...\n");
      goto GENERAL_ERROR;
  }
  goto FINISH;

GENERAL_ERROR:
  if (Fingerprint != NULL) {
    Fingerprint->Dispose(Fingerprint);
    Fingerprint = NULL;
  }

FINISH:
  return Fingerprint;
}

