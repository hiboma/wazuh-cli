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

fn main() {
    let cli = Cli::parse();

    // Capture `WAZUH_API_PASSWORD` and immediately scrub it from the
    // process environment, *before* any subcommand dispatch. This
    // closes the window in which `ps -E` / `/proc/<pid>/environ`
    // could read the plaintext, and it covers the `credentials`
    // subcommand path too (which does not consume the env var but
    // previously left it in place for the duration of the run).
    //
    // SAFETY: single-threaded context; no other thread observes env
    // mutations at this point in startup.
    let env_api_password: Option<zeroize::Zeroizing<String>> = {
        let v = std::env::var("WAZUH_API_PASSWORD").ok();
        unsafe { std::env::remove_var("WAZUH_API_PASSWORD") };
        v.filter(|s| !s.is_empty()).map(zeroize::Zeroizing::new)
    };

    // Subcommands that do not talk to the Wazuh API do not need a tokio
    // runtime and must run before any credential resolution that would
    // otherwise require API config. Handle them here.
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
        #[cfg(target_os = "macos")]
        Command::Credentials(cmd) => {
            // clap propagates `global = true` unconditionally, so the
            // API-specific options (--api-url, --api-password, etc.)
            // appear on `credentials`'s help even though they have no
            // effect here. Warn loudly if a user passes one so the
            // silent drop does not masquerade as success.
            if cli.global.api_url.is_some()
                || cli.global.api_user.is_some()
                || cli.global.api_password.is_some()
                || cli.global.ca_cert.is_some()
                || cli.global.client_cert.is_some()
                || cli.global.client_key.is_some()
                || cli.global.insecure
            {
                eprintln!(
                    "warning: API options (--api-url, --api-password, \
                     --ca-cert, ...) have no effect on `credentials`. \
                     Use --file / --stdin to provide the value to store."
                );
            }
            if let Err(e) = commands::credentials::run(cmd) {
                output::print_error(&e);
                process::exit(output::exit_code(&e));
            }
            return;
        }
        _ => {}
    }

    // Move the clap-parsed password straight into `Zeroizing` so the
    // only heap copy under our control is wiped on drop. The argv
    // copy itself is already exposed via `ps` and we cannot touch
    // that.
    let cli_opts = CliOpts {
        api_url: cli.global.api_url,
        api_user: cli.global.api_user,
        api_password: cli.global.api_password.map(zeroize::Zeroizing::new),
        ca_cert: cli.global.ca_cert,
        client_cert: cli.global.client_cert,
        client_key: cli.global.client_key,
        insecure: cli.global.insecure,
        output: cli.global.output,
        raw: cli.global.raw,
        progress: cli.global.progress,
        timeout: None,
    };

    // Pass the captured env password into resolution. We already
    // scrubbed the env var at startup so `from_cli_and_env` would
    // not find it now; the `from_cli_env_and_store` variant threads
    // the captured value through explicitly.
    let config = match Config::from_cli_env_and_store(
        &cli_opts,
        env_api_password.as_ref(),
        config::credential_store::default_store().as_ref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            output::print_error(&e);
            process::exit(output::exit_code(&e));
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to build tokio runtime: {e}");
            process::exit(1);
        }
    };

    let result = runtime.block_on(run(cli.command, &config));

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
        Command::Completion { .. } => unreachable!("handled before run()"),
        #[cfg(target_os = "macos")]
        Command::Credentials(_) => unreachable!("handled before run()"),
    }
}
