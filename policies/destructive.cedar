// Veto — destructive-operation governance policies
//
// Guards against destructive shell commands and file operations.

// ═══════════════════════════════════════════════════════
// §1  Filesystem Destruction
// ═══════════════════════════════════════════════════════

@id("forbid-rm-root")
@description("Block rm targeting the root filesystem.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm /" ||
    context.command like "*rm -* /"
};

@id("forbid-rm-home")
@description("Block rm targeting the home directory root.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm ~" ||
    context.command like "*rm ~/" ||
    context.command like "*rm -* ~" ||
    context.command like "*rm -* ~/"
};

@id("forbid-rm-hidden-home")
@description("Block recursive rm targeting hidden directories in $HOME.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm -r* ~/.*"
};

@id("forbid-rm-git")
@description("Block rm targeting .git directories.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm * .git" ||
    context.command like "*rm .git" ||
    context.command like "*rm * .git/" ||
    context.command like "*rm .git/" ||
    context.command like "*rm*/.git" ||
    context.command like "*rm*/.git/"
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
    context.command like "*shred *"
};

@id("forbid-wipe-dd")
@description("Block dd commands that write to block devices.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*dd *of=/dev/*"
};

@id("forbid-mkfs")
@description("Block filesystem creation commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*mkfs*"
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
@description("Block git filter-branch — rewrites repository history.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.program == "git" &&
    context.subcommand == "filter-branch"
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
    context.command like "*docker system prune*"
};

@id("forbid-docker-volume-rm")
@description("Block docker volume removal.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*docker volume rm *" ||
    context.command like "*docker volume prune*"
};

@id("forbid-kubectl-delete-namespace")
@description("Block kubectl delete namespace.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*kubectl delete namespace *" ||
    context.command like "*kubectl delete ns *"
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
// §4  Database Destruction
// ═══════════════════════════════════════════════════════

@id("forbid-drop-database")
@description("Block DROP DATABASE commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*DROP DATABASE*" ||
    context.command like "*drop database*" ||
    context.command like "*dropdb *"
};

@id("forbid-drop-table")
@description("Block DROP TABLE commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*DROP TABLE*" ||
    context.command like "*drop table*"
};

@id("forbid-truncate-table")
@description("Block TRUNCATE TABLE commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*TRUNCATE TABLE*" ||
    context.command like "*TRUNCATE *"
};

@id("forbid-redis-flushall")
@description("Block Redis FLUSHALL/FLUSHDB.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*FLUSHALL*" ||
    context.command like "*FLUSHDB*"
};

// ═══════════════════════════════════════════════════════
// §5  Package & Dependency Destruction
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
// §6  Recursive Permission Changes
// ═══════════════════════════════════════════════════════

@id("forbid-chmod-recursive-permissive")
@description("Block recursive chmod to overly permissive modes.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*chmod -R 777 *" ||
    context.command like "*chmod -R 666 *"
};

@id("forbid-chown-recursive-root")
@description("Block recursive chown to root.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*chown -R root *"
};

// ═══════════════════════════════════════════════════════
// §7  Kill & Process Termination
// ═══════════════════════════════════════════════════════

@id("forbid-killall")
@description("Block killall and pkill — mass process termination.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*killall *" ||
    context.command like "*pkill *"
};

@id("forbid-kill-signal-9")
@description("Block kill -9 — forcibly kills processes without cleanup.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*kill -9 *" ||
    context.command like "*kill -KILL *" ||
    context.command like "*kill -SIGKILL *"
};

// ═══════════════════════════════════════════════════════
// §8  Critical File Deletion Guards
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
