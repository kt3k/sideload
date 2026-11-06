use std::process::ExitCode;

fn main() -> ExitCode {
    sideload::cli::main(std::env::args_os())
}
