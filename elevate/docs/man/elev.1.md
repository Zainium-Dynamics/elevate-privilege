---
title: ELEV(1) elevate-zainium 0.2.13 | elevate-zainium
---

# NAME

`elev` - run a shell or command as another user

# SYNOPSIS

`elev` [options] [-] [<*user*> [<*argument*>...]]

# OPTIONS

`-c` *command*, `--command`=*command*
:   Pass a single command to the shell with `-c`.

`-g` *group*, `--group`=*group*
:   Specify the primary group

`-G` *group*, `--supp-group`=*group*
:   Specify a supplemental group

`-h`, `--help`
:   Show a help message.

`-`, `-l`, `--login`
:   Make the shell a login shell

`-m`, `-p`, `--preserve-environment`
:   Do not reset environment variables

`-P`, `--pty`
:   Ignored for backwards compatibility. This version of elev always creates
    a new pseudo-terminal if it is attached to a TTY

`-w` *list*, `--whitelist-environment`=*list*
:   Do not reset the environment variables specified by the *list*. Multiple
    variables can be separated by commas

`-s` *shell*, `--shell`=*shell*
:   Run *shell* if `/etc/shells` allows running as that shell instead of the
    default shell for the user

`-V`, `--version`
:   Show the program version

# SEE ALSO

[elevate(8)](elevate.8.md)
