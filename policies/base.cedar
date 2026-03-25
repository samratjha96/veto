// Veto — base governance policies
//
// Default-permit with targeted forbids.

@id("default-permit")
@description("Permit all actions unless a forbid fires.")
permit (principal, action, resource);

// ─── Shell Command Guards ────────────────────────────

@id("forbid-shell-critical-severity")
@description("Block shell commands that trigger critical-severity YARA rules.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.severity >= 4
};

// ─── WebFetch Guards ─────────────────────────────────

@id("forbid-webfetch-critical-severity")
@description("Block web fetches that trigger critical-severity YARA rules.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    context.signature.severity >= 4
};

// ─── File Operation Guards ───────────────────────────

@id("forbid-file-critical-severity")
@description("Block file operations that trigger critical-severity YARA rules.")
forbid (
    principal,
    action in [Action::"FileRead", Action::"FileWrite", Action::"FileEdit", Action::"FileDelete"],
    resource
) when {
    context.signature.severity >= 4
};
