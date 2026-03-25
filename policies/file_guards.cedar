// Veto — file operation guard policies
//
// Protects sensitive files and directories from write/edit/delete
// by AI coding agents. Covers system files, credentials, SSH
// configs, environment files, and security-critical configs.

// ═══════════════════════════════════════════════════════
// §1  System Files
// ═══════════════════════════════════════════════════════

@id("forbid-write-etc-passwd")
@description("Block writes to /etc/passwd and /etc/shadow.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/etc/passwd" ||
    context.path like "*/etc/shadow" ||
    context.path like "*/etc/sudoers" ||
    context.path like "*/etc/hosts"
};

@id("forbid-write-system-configs")
@description("Block writes to critical system configuration files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/etc/ssh/sshd_config" ||
    context.path like "*/etc/pam.d/*" ||
    context.path like "*/etc/security/*" ||
    context.path like "*/etc/crontab"
};

// ═══════════════════════════════════════════════════════
// §2  SSH & Credential Files
// ═══════════════════════════════════════════════════════

@id("forbid-write-ssh-keys")
@description("Block writes to SSH key files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.ssh/id_*" ||
    context.path like "*/.ssh/authorized_keys" ||
    context.path like "*/.ssh/known_hosts" ||
    context.path like "*/.ssh/config"
};

@id("forbid-delete-ssh-keys")
@description("Block deletion of SSH key files.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*/.ssh/id_*" ||
    context.path like "*/.ssh/authorized_keys" ||
    context.path like "*/.ssh/config"
};

@id("forbid-write-cloud-credentials")
@description("Block writes to cloud provider credential files.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.aws/credentials" ||
    context.path like "*/.aws/config" ||
    context.path like "*/.config/gcloud/credentials.db" ||
    context.path like "*/.azure/msal_token_cache*" ||
    context.path like "*/.kube/config"
};

// ═══════════════════════════════════════════════════════
// §3  Environment & Secret Files
// ═══════════════════════════════════════════════════════

@id("forbid-delete-env-files")
@description("Block deletion of .env files — may contain secrets.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*/.env" ||
    context.path like "*/.env.local" ||
    context.path like "*/.env.production" ||
    context.path like "*/.env.staging"
};

@id("forbid-write-shell-profiles")
@description("Block writes to shell profile files — persistence vector.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.bashrc" ||
    context.path like "*/.bash_profile" ||
    context.path like "*/.zshrc" ||
    context.path like "*/.zprofile" ||
    context.path like "*/.profile"
};

// ═══════════════════════════════════════════════════════
// §4  Security-Critical Project Files
// ═══════════════════════════════════════════════════════

@id("forbid-delete-security-configs")
@description("Block deletion of security configuration files.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*/.npmrc" ||
    context.path like "*/.pypirc" ||
    context.path like "*/renovate.json" ||
    context.path like "*/.snyk"
};

@id("forbid-write-git-hooks")
@description("Block writes to git hooks — could bypass pre-commit checks.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.git/hooks/*"
};

@id("forbid-delete-git-hooks")
@description("Block deletion of git hooks.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*/.git/hooks/*"
};
