/* elevate-pam — Linux-PAM compatible types
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */
#ifndef _SECURITY__PAM_TYPES_H
#define _SECURITY__PAM_TYPES_H

typedef struct pam_handle pam_handle_t;

#define __LINUX_PAM__ 1
#define __LINUX_PAM_MINOR__ 7

#define PAM_SUCCESS 0
#define PAM_OPEN_ERR 1
#define PAM_SYMBOL_ERR 2
#define PAM_SERVICE_ERR 3
#define PAM_SYSTEM_ERR 4
#define PAM_BUF_ERR 5
#define PAM_PERM_DENIED 6
#define PAM_AUTH_ERR 7
#define PAM_CRED_INSUFFICIENT 8
#define PAM_AUTHINFO_UNAVAIL 9
#define PAM_USER_UNKNOWN 10
#define PAM_MAXTRIES 11
#define PAM_NEW_AUTHTOK_REQD 12
#define PAM_ACCT_EXPIRED 13
#define PAM_SESSION_ERR 14
#define PAM_CRED_UNAVAIL 15
#define PAM_CRED_EXPIRED 16
#define PAM_CRED_ERR 17
#define PAM_NO_MODULE_DATA 18
#define PAM_CONV_ERR 19
#define PAM_AUTHTOK_ERR 20
#define PAM_AUTHTOK_RECOVERY_ERR 21
#define PAM_AUTHTOK_LOCK_BUSY 22
#define PAM_AUTHTOK_DISABLE_AGING 23
#define PAM_TRY_AGAIN 24
#define PAM_IGNORE 25
#define PAM_ABORT 26
#define PAM_AUTHTOK_EXPIRED 27
#define PAM_MODULE_UNKNOWN 28
#define PAM_BAD_ITEM 29
#define PAM_CONV_AGAIN 30
#define PAM_INCOMPLETE 31

#define PAM_SILENT 0x8000U
#define PAM_DISALLOW_NULL_AUTHTOK 0x0001U
#define PAM_ESTABLISH_CRED 0x0002U
#define PAM_DELETE_CRED 0x0004U
#define PAM_REINITIALIZE_CRED 0x0008U
#define PAM_REFRESH_CRED 0x0010U
#define PAM_CHANGE_EXPIRED_AUTHTOK 0x0020U

#define PAM_SERVICE 1
#define PAM_USER 2
#define PAM_TTY 3
#define PAM_RHOST 4
#define PAM_CONV 5
#define PAM_AUTHTOK 6
#define PAM_OLDAUTHTOK 7
#define PAM_RUSER 8
#define PAM_USER_PROMPT 9
#define PAM_FAIL_DELAY 10
#define PAM_XDISPLAY 11
#define PAM_XAUTHDATA 12
#define PAM_AUTHTOK_TYPE 13

#define PAM_PROMPT_ECHO_OFF 1
#define PAM_PROMPT_ECHO_ON 2
#define PAM_ERROR_MSG 3
#define PAM_TEXT_INFO 4

#define PAM_DATA_SILENT 0x40000000

struct pam_message {
    int msg_style;
    const char *msg;
};

struct pam_response {
    char *resp;
    int resp_retcode;
};

struct pam_conv {
    int (*conv)(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr);
    void *appdata_ptr;
};

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item);
int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);
const char *pam_strerror(pam_handle_t *pamh, int errnum);
int pam_putenv(pam_handle_t *pamh, const char *name_value);
const char *pam_getenv(pam_handle_t *pamh, const char *name);
char **pam_getenvlist(pam_handle_t *pamh);
int pam_fail_delay(pam_handle_t *pamh, unsigned int musec_delay);

#endif /* _SECURITY__PAM_TYPES_H */
