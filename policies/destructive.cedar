// Veto — destructive-operation governance policies
//
// Guards against destructive shell commands and file operations.

// ═══════════════════════════════════════════════════════
// §1  Filesystem Destruction
// ═══════════════════════════════════════════════════════

// Commands that delete or write files (rm, mv, cp, dd, redirects) are also
// checked as FileDelete/FileWrite actions on each path they touch, so these
// policies match the path, not the spelling of the command.

@id("forbid-delete-root")
@description("Block deleting the root filesystem.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path == "/" ||
    context.path == "/*"
};

@id("forbid-delete-home")
@description("Block deleting the home directory root.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path == "~" ||
    context.path == "~/*"
};

@id("forbid-delete-credential-dir")
@description("Block deleting the SSH, GnuPG or AWS credential directories.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*/.ssh" ||
    context.path like "*/.gnupg" ||
    context.path like "*/.aws"
};

@id("forbid-delete-git-dir")
@description("Block deleting a .git directory.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*/.git"
};

@id("ask-find-delete")
@description("Confirm before find deletes everything it matches.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "find" &&
    context.flags.contains("delete")
};

@id("forbid-shred")
@description("Block shred commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "shred"
};

@id("forbid-write-block-device")
@description("Block writing to disk devices (dd of=, redirects).")
forbid (
    principal,
    action == Action::"FileWrite",
    resource
) when {
    context.path like "/dev/sd*" ||
    context.path like "/dev/hd*" ||
    context.path like "/dev/vd*" ||
    context.path like "/dev/xvd*" ||
    context.path like "/dev/nvme*" ||
    context.path like "/dev/mmcblk*" ||
    context.path like "/dev/disk*" ||
    context.path like "/dev/rdisk*"
};

@id("forbid-mkfs")
@description("Block filesystem creation commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program like "mkfs*"
};

// ═══════════════════════════════════════════════════════
// §2  Git Destructive Operations
// ═══════════════════════════════════════════════════════

@id("forbid-git-force-push")
@description("Block git force push.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "git" &&
    context.subcommand == "push" &&
    (context.flags.contains("force") ||
     context.flags.contains("force-with-lease") ||
     context.flags.contains("force-if-includes"))
};

@id("ask-git-push-delete")
@description("Confirm before deleting a remote ref.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "git" &&
    context.subcommand == "push" &&
    context.flags.contains("delete")
};

@id("forbid-git-reset-hard")
@description("Block git reset --hard.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "git" &&
    context.subcommand == "reset" &&
    context.flags.contains("hard")
};

@id("forbid-git-clean-force")
@description("Block git clean -f.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "git" &&
    context.subcommand == "clean" &&
    context.flags.contains("force")
};

@id("forbid-git-no-verify")
@description("Block git operations with --no-verify.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "git" &&
    ["commit", "push"].contains(context.subcommand) &&
    context.flags.contains("no-verify")
};

@id("forbid-git-filter-branch")
@description("Block git filter-branch and filter-repo — rewrite repository history.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "git" &&
    ["filter-branch", "filter-repo"].contains(context.subcommand)
};

// ═══════════════════════════════════════════════════════
// §3  Infrastructure Teardown
// ═══════════════════════════════════════════════════════

@id("forbid-terraform-destroy")
@description("Block terraform destroy.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "terraform" &&
    (context.subcommand == "destroy" ||
     (context.subcommand == "apply" && context.flags.contains("destroy")))
};

@id("forbid-docker-system-prune")
@description("Block docker system prune.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "docker" &&
    context.subcommand == "system prune"
};

@id("forbid-docker-volume-rm")
@description("Block docker volume removal.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "docker" &&
    ["volume rm", "volume prune"].contains(context.subcommand)
};

@id("forbid-kubectl-delete-namespace")
@description("Block kubectl delete namespace.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "kubectl" &&
    context.subcommand == "delete namespace"
};

@id("forbid-helm-uninstall")
@description("Block helm uninstall.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "helm" &&
    context.subcommand == "uninstall"
};

// ═══════════════════════════════════════════════════════
// §4  Package & Dependency Destruction
// ═══════════════════════════════════════════════════════

@id("forbid-delete-lockfile")
@description("Block deletion of package lock files.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*package-lock.json" ||
    context.path like "*yarn.lock" ||
    context.path like "*pnpm-lock.yaml" ||
    context.path like "*Cargo.lock" ||
    context.path like "*poetry.lock" ||
    context.path like "*uv.lock" ||
    context.path like "*go.sum"
};

// ═══════════════════════════════════════════════════════
// §5  Recursive Permission Changes
// ═══════════════════════════════════════════════════════

@id("forbid-chmod-recursive-permissive")
@description("Block recursive chmod to overly permissive modes.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "chmod" &&
    context.flags.contains("recursive") &&
    (context.flags.contains("mode-777") || context.flags.contains("mode-666"))
};

// ═══════════════════════════════════════════════════════
// §6  Kill & Process Termination
// ═══════════════════════════════════════════════════════

@id("forbid-killall")
@description("Block killall and pkill — mass process termination.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    ["killall", "pkill"].contains(context.program)
};

@id("forbid-kill-signal-9")
@description("Block kill -9 and -KILL — forcibly kills processes without cleanup.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "kill" &&
    (context.flags.contains("9") ||
     (context.flags.contains("K") && context.flags.contains("I") && context.flags.contains("L")))
};

// ═══════════════════════════════════════════════════════
// §7  Critical File Deletion Guards
// ═══════════════════════════════════════════════════════

@id("forbid-delete-gitignore")
@description("Block deletion of .gitignore.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*.gitignore"
};

@id("forbid-delete-dockerfile")
@description("Block deletion of Dockerfiles.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*Dockerfile" ||
    context.path like "*docker-compose*.yml"
};

@id("forbid-delete-ci-config")
@description("Block deletion of CI/CD configuration files.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    context.path like "*.github/workflows/*.yml" ||
    context.path like "*.gitlab-ci.yml" ||
    context.path like "*Jenkinsfile"
};
