mod api;
mod cli;
mod client;
mod commands;
mod config;
mod error;
mod output;
mod secret;

use clap::{CommandFactory, Parser};
use clap_complete::generate;
use std::io::{self, StdoutLock, Write};
use std::process::ExitCode;

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

fn main() -> ExitCode {
    // Capture `WAZUH_API_PASSWORD` and immediately scrub it from the
    // process environment, *before* any subcommand dispatch. This
    // prevents later environment lookups and child inheritance, but does
    // not erase the original OS environment memory. It covers credentials
    // subcommand path too (which does not consume the env var but
    // previously left it in place for the duration of the run).
    //
    // SAFETY: single-threaded context; no other thread observes env
    // mutations at this point in startup.
    let (cli, env_api_password) = match parse_startup(std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(err) => {
            let code = err.exit_code() as u8;
            let _ = err.print();
            return ExitCode::from(code);
        }
    };
    if cli.global.api_password_stdin && command_reads_secret_stdin(&cli.command) {
        eprintln!("error: API password and command secret cannot both read stdin");
        return ExitCode::from(2);
    }

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
                return ExitCode::from(1);
            }
            return ExitCode::SUCCESS;
        }
        #[cfg(target_os = "macos")]
        Command::Credentials(cmd) => {
            // clap propagates `global = true` unconditionally, so the
            // API-specific options (--api-url, --ca-cert, etc.)
            // appear on `credentials`'s help even though they have no
            // effect here. Warn loudly if a user passes one so the
            // silent drop does not masquerade as success.
            if cli.global.api_url.is_some()
                || cli.global.api_user.is_some()
                || cli.global.ca_cert.is_some()
                || cli.global.client_cert.is_some()
                || cli.global.client_key.is_some()
                || cli.global.insecure
                || cli.global.api_password_stdin
                || cli.global.api_password_file.is_some()
            {
                eprintln!(
                    "warning: API options (--api-url, --api-user, \
                     --ca-cert, ...) have no effect on `credentials`. \
                     Use --file / --stdin to provide the value to store."
                );
            }
            if let Err(e) = commands::credentials::run(cmd) {
                output::print_error(&e);
                return ExitCode::from(output::exit_code(&e) as u8);
            }
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let api_password = if cli.global.api_password_stdin || cli.global.api_password_file.is_some() {
        match secret::read_secret(
            secret::SecretSource::from_flags(
                cli.global.api_password_stdin,
                cli.global.api_password_file.as_deref(),
            ),
            "API password (input hidden): ",
            false,
        ) {
            Ok(value) => Some(value),
            Err(e) => {
                output::print_error(&e);
                return ExitCode::from(output::exit_code(&e) as u8);
            }
        }
    } else {
        env_api_password
    };
    let secret_output_file = cli.global.secret_output_file;
    let cli_opts = CliOpts {
        api_url: cli.global.api_url,
        api_user: cli.global.api_user,
        ca_cert: cli.global.ca_cert,
        client_cert: cli.global.client_cert,
        client_key: cli.global.client_key,
        insecure: cli.global.insecure,
        output: cli.global.output,
        raw: cli.global.raw,
        progress: cli.global.progress,
        timeout: None,
        config: cli.global.config,
    };

    // Load the TOML config file before resolution so its values
    // participate in the merge. `file::load` returns Ok(None) when
    // neither --config nor WAZUH_CONFIG was set and the default
    // path does not exist, and Err(..) for a user-supplied path
    // that cannot be read / parsed (so typos surface loudly).
    let loaded_file = match config::file::load(
        cli_opts.config.as_deref(),
        std::env::var("WAZUH_CONFIG").ok().as_deref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            output::print_error(&e);
            return ExitCode::from(output::exit_code(&e) as u8);
        }
    };
    let file_cfg = loaded_file.as_ref().map(|(_, f)| f);

    // Pass the captured env password into resolution. We already
    // scrubbed the env var at startup so a fresh `std::env::var`
    // lookup would not find it now; thread the captured value
    // through explicitly.
    let config = match Config::from_cli_env_store_and_file(
        &cli_opts,
        api_password.as_ref(),
        config::credential_store::default_store().as_ref(),
        file_cfg,
    ) {
        Ok(c) => c,
        Err(e) => {
            output::print_error(&e);
            return ExitCode::from(output::exit_code(&e) as u8);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to build tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let result = runtime.block_on(run(cli.command, &config));

    match result {
        Ok(value) => {
            if let Some(path) = secret_output_file
                && let Err(e) = output::write_secret_response(&path, &value)
            {
                output::print_error(&e);
                return ExitCode::from(output::exit_code(&e) as u8);
            }
            if let Err(e) = output::print_response(&value, config.output_format, config.raw_output)
            {
                output::print_error(&e);
                return ExitCode::from(output::exit_code(&e) as u8);
            }
        }
        Err(e) => {
            output::print_error(&e);
            return ExitCode::from(output::exit_code(&e) as u8);
        }
    }
    ExitCode::SUCCESS
}

fn command_reads_secret_stdin(command: &Command) -> bool {
    use cli::other::LogtestAction;
    use cli::security::{SecurityAction, SecurityUserAction};
    match command {
        Command::Security(cmd) => match &cmd.action {
            SecurityAction::User(cmd) => match &cmd.action {
                SecurityUserAction::Create { password, .. }
                | SecurityUserAction::Update { password, .. } => password.password_stdin,
                _ => false,
            },
            _ => false,
        },
        Command::Logtest(cmd) => match &cmd.action {
            LogtestAction::Run { session_stdin, .. } => *session_stdin,
            LogtestAction::DeleteSession { token_stdin, .. } => *token_stdin,
        },
        #[cfg(target_os = "macos")]
        Command::Credentials(cmd) => matches!(
            cmd.action,
            cli::credentials::CredentialsAction::Set { stdin: true, .. }
        ),
        _ => false,
    }
}

/// Must be called before argument parsing and before starting worker threads.
fn capture_env_password() -> Option<zeroize::Zeroizing<String>> {
    let value = std::env::var("WAZUH_API_PASSWORD").ok();
    // SAFETY: main invokes this before any worker threads are created.
    unsafe { std::env::remove_var("WAZUH_API_PASSWORD") };
    value.filter(|s| !s.is_empty()).map(zeroize::Zeroizing::new)
}

/// Capture before parsing, including help, version and argument errors.
/// Call only during single-threaded process startup.
fn parse_startup<I, T>(args: I) -> Result<(Cli, Option<zeroize::Zeroizing<String>>), clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let password = capture_env_password();
    let cli = Cli::try_parse_from(args)?;
    Ok((cli, password))
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
        Command::Experimental(cmd) => api::experimental::run(&client, cmd).await,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_scrubs_environment_before_all_parser_exit_paths() {
        fn isolated_test() -> std::process::Command {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "tests::capture_scrubs_environment_before_all_parser_exit_paths",
                "--test-threads=1",
            ]);
            command
        }

        let case = std::env::var("WAZUH_TEST_CAPTURE_CHILD").ok();
        let Some(case) = case else {
            for case in ["help", "version", "invalid", "success"] {
                let status = isolated_test()
                    .env("WAZUH_TEST_CAPTURE_CHILD", case)
                    .env("WAZUH_API_PASSWORD", "test-only-marker")
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            return;
        };
        if case == "observe" {
            // This process inherits the environment without an explicit removal.
            assert!(std::env::var_os("WAZUH_API_PASSWORD").is_none());
            return;
        }
        let argument = match case.as_str() {
            "help" => "--help",
            "version" => "--version",
            "invalid" => "invalid-command",
            "success" => "api-info",
            _ => panic!("unexpected test case"),
        };
        let result = parse_startup(["wazuh-cli", argument]);
        match case.as_str() {
            "success" => {
                let (_, password) = result.unwrap();
                assert_eq!(password.unwrap().as_str(), "test-only-marker");
            }
            "help" => assert_eq!(
                result.err().unwrap().kind(),
                clap::error::ErrorKind::DisplayHelp
            ),
            "version" => assert_eq!(
                result.err().unwrap().kind(),
                clap::error::ErrorKind::DisplayVersion
            ),
            _ => assert!(result.is_err()),
        }
        assert!(std::env::var_os("WAZUH_API_PASSWORD").is_none());
        let status = isolated_test()
            .env("WAZUH_TEST_CAPTURE_CHILD", "observe")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
