/* zainium-logind-session -- register a logind session as root, drop to the
 * session user, then exec the session command.
 *
 * Replaces pam_systemd.so, which cannot work under elevate-pam: it statically
 * links libpam and reads the handle using Linux-PAM's own struct layout. As a
 * `session optional` module it failed silently, so no logind session existed
 * and libseat's logind backend could not acquire one.
 *
 * CreateSession is root-only, so -- like pam_systemd -- this must run before
 * privileges are dropped: greetd's session worker execs it as root after
 * setgroups/setgid, and this helper does the setuid itself.
 *
 * Usage: zainium-logind-session --uid UID [--class CLASS] [--service NAME]
 *                               [--tty TTYN] -- COMMAND [ARGS...]
 *
 * Registration failures are logged and ignored (the `session optional`
 * semantics this replaces). Failing to drop privileges is never ignored.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <syslog.h>
#include <unistd.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-journal.h>

static void logmsg(int prio, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    /* stderr is the session's VT, which greetd clears -- keep a journal copy */
    sd_journal_print(prio, "zainium-logind-session: %s", buf);
    fprintf(stderr, "zainium-logind-session: %s\n", buf);
}

static const char *env_or(const char *k, const char *d) {
    const char *v = getenv(k);
    return (v && *v) ? v : d;
}

static void register_session(uid_t uid, const char *class, const char *service,
                             const char *tty) {
    sd_bus *bus = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    uint32_t vtnr = (uint32_t) strtoul(env_or("XDG_VTNR", "0"), NULL, 10);
    int r;

    r = sd_bus_open_system(&bus);
    if (r < 0) {
        logmsg(LOG_ERR, "cannot reach system bus: %s", strerror(-r));
        return;
    }

    r = sd_bus_call_method(bus,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "CreateSession",
            &err, &reply,
            "uussssussbssa(sv)",
            (uint32_t) uid,
            (uint32_t) getpid(),
            service,
            env_or("XDG_SESSION_TYPE", "wayland"),
            class,
            env_or("XDG_SESSION_DESKTOP", ""),
            env_or("XDG_SEAT", "seat0"),
            vtnr,
            tty,
            "",         /* display */
            0,          /* remote */
            "", "",     /* remote user, remote host */
            0);         /* no extra properties */
    if (r < 0) {
        logmsg(LOG_ERR, "CreateSession(uid=%u class=%s tty=%s vt=%u) failed: %s",
               (unsigned) uid, class, *tty ? tty : "-", vtnr,
               err.message ? err.message : strerror(-r));
        goto out;
    }

    const char *id = NULL, *path = NULL, *runtime = NULL, *seat = NULL;
    int fifo = -1, existing = 0;
    uint32_t out_uid = 0, out_vt = 0;

    r = sd_bus_message_read(reply, "soshusub", &id, &path, &runtime, &fifo,
                            &out_uid, &seat, &out_vt, &existing);
    if (r < 0) {
        logmsg(LOG_ERR, "malformed CreateSession reply: %s", strerror(-r));
        goto out;
    }

    /* the fifo is the session lease: keep a non-CLOEXEC copy across exec */
    if (fifo >= 0 && fcntl(fifo, F_DUPFD, 3) < 0)
        logmsg(LOG_WARNING, "cannot keep session fifo: %s", strerror(errno));

    if (id && *id)           setenv("XDG_SESSION_ID", id, 1);
    if (runtime && *runtime) setenv("XDG_RUNTIME_DIR", runtime, 1);
    if (seat && *seat)       setenv("XDG_SEAT", seat, 1);
    if (out_vt) {
        char vt[16];
        snprintf(vt, sizeof vt, "%u", out_vt);
        setenv("XDG_VTNR", vt, 1);
    }

    logmsg(LOG_INFO, "session %s uid=%u class=%s seat=%s vt=%u%s",
           id ? id : "?", (unsigned) uid, class, seat ? seat : "-", out_vt,
           existing ? " (existing)" : "");

out:
    sd_bus_error_free(&err);
    sd_bus_message_unref(reply);
    sd_bus_flush_close_unref(bus);
}

int main(int argc, char *argv[]) {
    const char *uid_s = NULL, *class = "user", *service = "greetd", *tty = "";
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { i++; break; }
        if (i + 1 >= argc) { i = argc; break; }
        if      (!strcmp(argv[i], "--uid"))     uid_s   = argv[++i];
        else if (!strcmp(argv[i], "--class"))   class   = argv[++i];
        else if (!strcmp(argv[i], "--service")) service = argv[++i];
        else if (!strcmp(argv[i], "--tty"))     tty     = argv[++i];
        else { logmsg(LOG_ERR, "unknown option %s", argv[i]); return 2; }
    }
    if (!uid_s || i >= argc) {
        fprintf(stderr, "usage: %s --uid UID [--class CLASS] [--service NAME] "
                        "[--tty TTYN] -- COMMAND [ARGS...]\n", argv[0]);
        return 2;
    }

    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(uid_s, &end, 10);
    if (errno || !*uid_s || *end || parsed >= (uid_t) -1) {
        logmsg(LOG_ERR, "invalid --uid %s", uid_s);
        return 2;
    }
    uid_t uid = (uid_t) parsed;

    if (geteuid() == 0)
        register_session(uid, class, service, tty);
    else
        logmsg(LOG_ERR, "not root -- cannot register a logind session");

    if (setuid(uid) < 0 || getuid() != uid || geteuid() != uid) {
        logmsg(LOG_CRIT, "setuid(%u) failed: %s -- refusing to run session",
               (unsigned) uid, strerror(errno));
        return 1;
    }

    /* setuid() clears the parent-death signal; re-arm it like greetd does */
    prctl(PR_SET_PDEATHSIG, SIGTERM);

    execv(argv[i], &argv[i]);
    logmsg(LOG_ERR, "exec %s: %s", argv[i], strerror(errno));
    return 127;
}
