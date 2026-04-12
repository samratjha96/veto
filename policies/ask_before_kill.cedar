@id("ask-before-kill")
@description("Prompt user before killing any process.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "kill *" ||
    context.command like "* kill *" ||
    context.command like "pkill *" ||
    context.command like "* pkill *" ||
    context.command like "killall *" ||
    context.command like "* killall *"
};
