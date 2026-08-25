# /etc/elevators/elevate.toml.d

Drop-in privilege rules for elevate.

- Files are read in sorted lexical order.
- Skip names that contain a '.' or end in '~' (package/editor backups).
- Use numeric prefixes: 10-local, 20-site, …
- Syntax is classic sudoers (same as /etc/elevators/elevate.toml), not TOML tables.

Example file name (no dots in the base name):

    10-wheel

Example content:

    %wheel ALL=(ALL:ALL) ALL
