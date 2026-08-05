---
title: VISELEV(8) elevate-zainium 0.2.13 | elevate-zainium
---

# NAME

`viselev` - safely edit the elevate.toml configuration file

# SYNOPSIS

`viselev` [`-chqsV`] [[`-f`] *elevate.toml*]

# DESCRIPTION

`viselev` edits the *elevate.toml* file in a safe manner, similar to vipw(8).

# OPTIONS

`-c`, `--check`
:   Only check if there are errors in the existing elevate.toml file.

`-f` *elevate.toml*, `--file`=*elevate.toml*
:   Instead of editing the default `/etc/elevators/elevate.toml`, edit the
    file specified as *elevate.toml* instead.

`-h`, `--help`
:   Show a help message.

`-V`, `--version`
:   Display version information and exit.

# SEE ALSO

[elevate(8)](elevate.8.md), elevate.toml(5)
