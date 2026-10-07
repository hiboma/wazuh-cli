use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cli::security::*;
use crate::client::WazuhClient;
use crate::error::WazuhError;
use crate::secret::{SecretSource, read_secret};

const PAGE_SIZE: u32 = 500;

/// Read a user password from the source selected by `PasswordInput`.
/// The prompt asks twice because this sets a password.
///
/// The returned value is wiped on drop. The copy inside the
/// `serde_json::Value` request body is not, which is unavoidable
/// without a custom serializer.
fn read_user_password(input: &PasswordInput, label: &str) -> Result<Zeroizing<String>, WazuhError> {
    let source = SecretSource::from_flags(input.password_stdin, input.password_file.as_deref());
    read_secret(source, &format!("{} (input hidden): ", label), true)
}

pub async fn run(client: &WazuhClient, cmd: SecurityCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        SecurityAction::Login => {
            // WazuhClient authenticates automatically; call GET /security/users/me to verify token validity
            client.get("/security/users/me", &[]).await
        }
        SecurityAction::Logout => client.delete("/security/user/authenticate", &[]).await,
        SecurityAction::User(user_cmd) => run_user(client, user_cmd).await,
        SecurityAction::Role(role_cmd) => run_role(client, role_cmd).await,
        SecurityAction::Policy(policy_cmd) => run_policy(client, policy_cmd).await,
        SecurityAction::Rule(rule_cmd) => run_rule(client, rule_cmd).await,
        SecurityAction::Config => client.get("/security/config", &[]).await,
        SecurityAction::UpdateConfig => client.put("/security/config", &json!({})).await,
        SecurityAction::ResetConfig => client.delete("/security/config", &[]).await,
    }
}

async fn run_user(client: &WazuhClient, cmd: SecurityUserCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        SecurityUserAction::List => {
            client
                .get_all_pages("/security/users", &[], PAGE_SIZE)
                .await
        }
        SecurityUserAction::GetMe => client.get("/security/users/me", &[]).await,
        SecurityUserAction::Create { username, password } => {
            let pw =
                read_user_password(&password, &format!("Password for new user '{}'", username))?;
            client
                .post(
                    "/security/users",
                    &json!({"username": username, "password": pw.as_str()}),
                )
                .await
        }
        SecurityUserAction::Update { user_id, password } => {
            let pw =
                read_user_password(&password, &format!("New password for user ID {}", user_id))?;
            let path = format!("/security/users/{}", user_id);
            client.put(&path, &json!({"password": pw.as_str()})).await
        }
        SecurityUserAction::Delete { user_ids } => {
            let ids = user_ids.join(",");
            client
                .delete("/security/users", &[("user_ids", &ids)])
                .await
        }
    }
}

async fn run_role(client: &WazuhClient, cmd: SecurityRoleCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        SecurityRoleAction::List => {
            client
                .get_all_pages("/security/roles", &[], PAGE_SIZE)
                .await
        }
        SecurityRoleAction::Create { name } => {
            client.post("/security/roles", &json!({"name": name})).await
        }
        SecurityRoleAction::Update { role_id } => {
            let path = format!("/security/roles/{}", role_id);
            client.put(&path, &json!({})).await
        }
        SecurityRoleAction::Delete { role_ids } => {
            let ids = role_ids.join(",");
            client
                .delete("/security/roles", &[("role_ids", &ids)])
                .await
        }
    }
}

async fn run_policy(client: &WazuhClient, cmd: SecurityPolicyCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        SecurityPolicyAction::List => {
            client
                .get_all_pages("/security/policies", &[], PAGE_SIZE)
                .await
        }
        SecurityPolicyAction::Create { name } => {
            client
                .post("/security/policies", &json!({"name": name}))
                .await
        }
        SecurityPolicyAction::Update { policy_id } => {
            let path = format!("/security/policies/{}", policy_id);
            client.put(&path, &json!({})).await
        }
        SecurityPolicyAction::Delete { policy_ids } => {
            let ids = policy_ids.join(",");
            client
                .delete("/security/policies", &[("policy_ids", &ids)])
                .await
        }
    }
}

async fn run_rule(client: &WazuhClient, cmd: SecurityRuleCommand) -> Result<Value, WazuhError> {
    match cmd.action {
        SecurityRuleAction::List => {
            client
                .get_all_pages("/security/rules", &[], PAGE_SIZE)
                .await
        }
        SecurityRuleAction::Create => client.post("/security/rules", &json!({})).await,
        SecurityRuleAction::Update { rule_id } => {
            let path = format!("/security/rules/{}", rule_id);
            client.put(&path, &json!({})).await
        }
        SecurityRuleAction::Delete { rule_ids } => {
            let ids = rule_ids.join(",");
            client
                .delete("/security/rules", &[("rule_ids", &ids)])
                .await
        }
    }
}
