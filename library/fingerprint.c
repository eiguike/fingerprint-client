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

unsigned char*
EncodeToB64 (
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
DecodeFromB64 (
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

  //printf("SIZE %ld\n", Size);
  //printf("DECODELEN %ld\n", *DecodeLen);

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
  int                    Index = 0;

  if (This == NULL) {
    goto FINISH;
  }

  // Deallocating previously fingerprint list
  if (This->FingerprintList != NULL) {
    for (Index = 0; Index < This->NumberOfFingerprints; Index++) {
      fp_print_data_free(This->FingerprintList[Index]);
    }
    free(This->FingerprintList);
    This->FingerprintList = NULL;
  }

  // Deallocating previously UserId list
  if (This->UserIdList != NULL) {
    free(This->UserIdList);
    This->UserIdList = NULL;
  }

  File = fopen("sigla_database.db", "rb");

  if (File == NULL) {
    printf("fopen returned NULL %d\n", __LINE__);
    Status = 1;
    goto FINISH;
  }

  while(fscanf(File, "%d|%[^\n]", &FingerprintInstance.UserId, FingerprintInstance.Fingerprint) != EOF) {
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

    Buffer = DecodeFromB64(FingerprintInstance.Fingerprint, 16068, &DecodeLen);
    if (Buffer == NULL) {
      Status = 1;
      goto GENERAL_ERROR;
    }

    Fingerprints[NoFingerprints - 1] = fp_print_data_from_data(Buffer, DecodeLen);
    UserIds[NoFingerprints - 1] = FingerprintInstance.UserId;

    if (Fingerprints[NoFingerprints - 1] == NULL ) {
      printf("could not ready entry from cache file\n");
      Status = 1;
      goto GENERAL_ERROR;
    }

    free(Buffer);
    Buffer = NULL;
  }

  NoFingerprints++;
  Fingerprints = realloc(Fingerprints, sizeof(struct fp_print_data*) * NoFingerprints);
  if (Fingerprints == NULL) {
    Status = 1;
    goto GENERAL_ERROR;
  }
  Fingerprints[NoFingerprints - 1] = NULL;

  This->FingerprintList = Fingerprints;
  This->UserIdList = UserIds;
  This->NumberOfFingerprints = NoFingerprints - 1;

  goto FINISH;

GENERAL_ERROR:
  if (This->FingerprintList != NULL) {
    //fp_print_data_free(This->FingerprintList);
    This->FingerprintList = NULL;
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

  if (File != NULL) {
    fclose(File);
  }

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

  JsonData = cJSON_Parse((char*)This->Data[0]);
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
  printf("Fingerprint_Write End\n");
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
  int Index = 0;

  if (This != NULL) {
    if (This->Data != NULL) {
      for (Index = 0; Index < This->NumberOfPackets; Index++) {
        if (This->Data[Index] != NULL) {
          free(This->Data[Index]);
          This->Data[Index] = NULL;
        }
      }
      free(This->Data);
      This->Data = NULL;
    }
    if (This->FingerprintList != NULL) {
      for (Index = 0; Index < This->NumberOfFingerprints; Index++) {
        fp_print_data_free(This->FingerprintList[Index]);
      }
      free(This->FingerprintList);
      This->FingerprintList = NULL;
    }
    if (This->UserIdList != NULL) {
      free(This->UserIdList);
      This->UserIdList = NULL;
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
  int          Size = 0;
  int          LastIndex = 0;
  int          Index = 0;

  if (userdata == NULL) {
    printf("Userdata == NULL %d\n", __LINE__);
    goto FINISH;
  }

  This = (FINGERPRINT*) userdata;

  if (This->LargePacket < nmemb) {
    This->LargePacket = nmemb;
  }

  if (strlen(ptr) == nmemb) {
    This->Data = realloc(This->Data, sizeof(char*) * (This->NumberOfPackets + 1));
    Aux = (char*) calloc(1, nmemb + 1);
    strcpy(Aux, ptr);
    This->Data[This->NumberOfPackets] = Aux;
    This->NumberOfPackets += 1;
  } else {
    This->NumberOfPackets += 1;
    Aux = (char*) calloc(1, This->NumberOfPackets * This->LargePacket);

    for (Index = 0; Index < This->NumberOfPackets - 1; Index++) {
      Size = strlen(This->Data[Index]);
      strcpy(Aux + LastIndex, This->Data[Index]);
      if (Index == 0) {
        LastIndex += Size - 1;
      } else {
        LastIndex += Size;
      }
      free(This->Data[Index]);
    }
    strncpy(Aux + LastIndex, ptr, nmemb);

    This->Data = realloc(This->Data, sizeof(char*) + 1);
    This->Data[0] = Aux;
    This->Data[1] = NULL;
    This->NumberOfPackets = 2;
  }

FINISH:
  return size * nmemb;
}

int
Fingerprint_Send (
    FINGERPRINT* This
    )
{
  return 0;
}

int
Fingerprint_Add (
    FINGERPRINT* This,
    FINGERPRINT_FILE_ENROLL* Fingerprint
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
  int       Index = 0;
  CURL*     Curl = NULL;
  CURLcode  Resource = 0;
  char*     LocalUrl = NULL;
  char*     Body = NULL;
  char*     AccessBody = "embedded_password=%s";
  char*     AccessUrl = "/api/fingerprint/";

  if (This == NULL) {
    Status = 1;
    goto FINISH;
  }

  printf("fingerprint.c %d\n", __LINE__);
  Curl = curl_easy_init();

  if (Curl == NULL) {
    printf("Couldn't get a curl handler!!\n");
    Status = 1;
    goto FINISH;
  } else {
    Body = realloc(Body, strlen(AccessBody) + strlen(gPassword) + 1);
    sprintf(Body, AccessBody, gPassword);
    LocalUrl = realloc(LocalUrl, strlen(gUrl) + strlen(AccessUrl) + 1);
    sprintf(LocalUrl, "%s%s", gUrl, AccessUrl);
    printf("%s\n", LocalUrl);
    printf("%s\n", Body);

    curl_easy_setopt(Curl, CURLOPT_URL, LocalUrl);

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
    printf("fingerprint.c %d\n", __LINE__);
  }

  Fingerprint_Write (This);

FINISH:
  printf("Fingerprint_Update End\n");

  if (Curl != NULL) {
    curl_easy_cleanup(Curl);
    Curl = NULL;
  }
  if (This->Data != NULL) {
    for (Index = 0; Index < This->NumberOfPackets; Index++) {
      if (This->Data[Index] != NULL) {
        free(This->Data[Index]);
        This->Data[Index] = NULL;
      }
    }
    free(This->Data);
    This->Data = NULL;
  }

  if (Body != NULL) {
    free(Body);
    Body = NULL;
  }
  if (LocalUrl != NULL) {
    free(LocalUrl);
    LocalUrl = NULL;
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
  Fingerprint->Send = Fingerprint_Send;

  Fingerprint->Update = Fingerprint_Update;
  Fingerprint->Load = Fingerprint_Load;

  Fingerprint->Dispose = Fingerprint_Dispose;

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

