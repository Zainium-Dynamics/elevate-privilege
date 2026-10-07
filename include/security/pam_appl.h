/* elevate-pam — Linux-PAM compatible application API
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */
#ifndef _SECURITY_PAM_APPL_H
#define _SECURITY_PAM_APPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <security/_pam_types.h>

int pam_start(const char *service_name, const char *user,
              const struct pam_conv *pam_conversation,
              pam_handle_t **pamh);

int pam_start_confdir(const char *service_name, const char *user,
                      const struct pam_conv *pam_conversation,
                      const char *confdir, pam_handle_t **pamh);

int pam_end(pam_handle_t *pamh, int pam_status);

int pam_authenticate(pam_handle_t *pamh, int flags);
int pam_setcred(pam_handle_t *pamh, int flags);
int pam_acct_mgmt(pam_handle_t *pamh, int flags);
int pam_open_session(pam_handle_t *pamh, int flags);
int pam_close_session(pam_handle_t *pamh, int flags);
int pam_chauthtok(pam_handle_t *pamh, int flags);

#ifdef __cplusplus
}
#endif

#endif /* _SECURITY_PAM_APPL_H */
