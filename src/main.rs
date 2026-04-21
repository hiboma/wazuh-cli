mod api;
mod cli;
mod client;
mod commands;
mod config;
mod error;
mod output;

use clap::{CommandFactory, Parser};
use clap_complete::generate;
use std::io::{self, StdoutLock, Write};
use std::process;

use cli::{Cli, Command};
use config::{CliOpts, Config};

// `clap_complete::generate` calls `write_all` internally and unwraps any
// error. If the caller pipes the output to `head` (or similar), the pipe is
// closed early and the write fails with `BrokenPipe`, which would otherwise
// panic. This wrapper claims success on `BrokenPipe` so `generate` can finish
// cleanly; every other error is propagated as-is.
struct BrokenPipeTolerantStdout<'a>(StdoutLock<'a>);

impl Write for BrokenPipeTolerantStdout<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.write(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(buf.len()),
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0.flush() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Subcommands that do not talk to the Wazuh API are handled before
    // building the API client.
    match cli.command {
        Command::Completion { shell } => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            let stdout = io::stdout();
            let mut out = BrokenPipeTolerantStdout(stdout.lock());
            generate(shell, &mut cmd, bin_name, &mut out);
            if let Err(e) = out.flush() {
                eprintln!("error: failed to flush stdout: {e}");
                process::exit(1);
            }
            return;
        }
        Command::Credentials(cmd) => {
            if let Err(e) = commands::credentials::run(cmd) {
                output::print_error(&e);
                process::exit(output::exit_code(&e));
            }
            return;
        }
        _ => {}
    }

    let cli_opts = CliOpts {
        api_url: cli.global.api_url,
        api_user: cli.global.api_user,
        api_password: cli.global.api_password,
        ca_cert: cli.global.ca_cert,
        client_cert: cli.global.client_cert,
        client_key: cli.global.client_key,
        insecure: cli.global.insecure,
        output: cli.global.output,
        raw: cli.global.raw,
        progress: cli.global.progress,
        timeout: None,
    };

    let config = match Config::from_cli_and_env(&cli_opts) {
        Ok(c) => c,
        Err(e) => {
            output::print_error(&e);
            process::exit(output::exit_code(&e));
        }
    };

    let result = run(cli.command, &config).await;

    match result {
        Ok(value) => {
            if let Err(e) = output::print_response(&value, config.output_format, config.raw_output)
            {
                output::print_error(&e);
                process::exit(output::exit_code(&e));
            }
        }
        Err(e) => {
            output::print_error(&e);
            process::exit(output::exit_code(&e));
        }
    }
}

async fn run(command: Command, config: &Config) -> Result<serde_json::Value, error::WazuhError> {
    let client = client::WazuhClient::new(config).await?;

    match command {
        Command::Agent(cmd) => api::agent::run(&client, cmd).await,
        Command::Group(cmd) => api::group::run(&client, cmd).await,
        Command::Manager(cmd) => api::manager::run(&client, cmd).await,
        Command::Security(cmd) => api::security::run(&client, cmd).await,
        Command::Rule(cmd) => api::rule::run(&client, cmd).await,
        Command::Decoder(cmd) => api::decoder::run(&client, cmd).await,
        Command::Cluster(cmd) => api::cluster::run(&client, cmd).await,
        Command::Syscheck(cmd) => api::syscheck::run(&client, cmd).await,
        Command::Syscollector(cmd) => api::syscollector::run(&client, cmd).await,
        Command::Rootcheck(cmd) => api::rootcheck::run(&client, cmd).await,
        Command::Sca(cmd) => api::sca::run(&client, cmd).await,
        Command::Mitre(cmd) => api::mitre::run(&client, cmd).await,
        Command::List(cmd) => api::list::run(&client, cmd).await,
        Command::Logtest(cmd) => api::logtest::run(&client, cmd).await,
        Command::Task(cmd) => api::task::run(&client, cmd).await,
        Command::Event(cmd) => api::event::run(&client, cmd).await,
        Command::ActiveResponse(cmd) => api::active_response::run(&client, cmd).await,
        Command::Overview(cmd) => api::overview::run(&client, cmd).await,
        Command::ApiInfo => api::api_info::run(&client).await,
        Command::Completion { .. } | Command::Credentials(_) => {
            unreachable!("handled before run()")
        }
    }
}
