pub(crate) const USAGE_MSG: &str = "usage: viselev [-chqsV] [[-f] elevate.toml ]";

const DESCRIPTOR: &str = "viselev - safely edit the elevate.toml configuration file";

const HELP_MSG: &str = "Options:
  -c, --check              check-only mode
  -f, --file=elevators       specify elevators file location
  -h, --help               display help message and exit
  -V, --version            display version information and exit
";

pub(crate) fn long_help_message() -> String {
    format!("{USAGE_MSG}\n\n{DESCRIPTOR}\n\n{HELP_MSG}")
}
