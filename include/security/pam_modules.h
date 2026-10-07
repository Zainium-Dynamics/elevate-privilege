/* elevate-pam — module API
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */
#ifndef _SECURITY_PAM_MODULES_H
#define _SECURITY_PAM_MODULES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <security/_pam_types.h>

int pam_set_data(pam_handle_t *pamh, const char *module_data_name, void *data,
                 void (*cleanup)(pam_handle_t *pamh, void *data, int error_status));
int pam_get_data(const pam_handle_t *pamh, const char *module_data_name,
                 const void **data);
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv);

#define PAM_PRELIM_CHECK 0x4000
#define PAM_UPDATE_AUTHTOK 0x2000
#define PAM_DATA_REPLACE 0x20000000
#define PAM_EXTERN extern

#ifdef __cplusplus
}
#endif

#endif /* _SECURITY_PAM_MODULES_H */
