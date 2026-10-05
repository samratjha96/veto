@id("ask-before-kill")
@description("Prompt user before killing any process.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    ["kill", "pkill", "killall"].contains(context.program)
};
