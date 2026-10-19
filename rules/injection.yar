/*
 * Command Injection Detection Rules
 */

rule command_injection_dangerous_commands {
    meta:
        description = "Detects execution of dangerous system commands"
        severity = "critical"
        category = "command_injection"

    strings:
        $curl_pipe = /curl[^|]*\|\s*(sh|bash)/ nocase
        $wget_exec = /wget[^&]*&&\s*(sh|bash)/ nocase

    condition:
        any of them
}

rule command_injection_sensitive_files {
    meta:
        description = "Detects access to sensitive system files"
        severity = "critical"
        category = "command_injection"

    strings:
        $passwd = "/etc/passwd" nocase
        $shadow = "/etc/shadow" nocase
        $ssh_priv = "/.ssh/id_rsa" nocase
        $ssh_keys = "/.ssh/authorized_keys" nocase
        $aws = "/.aws/credentials" nocase
        $gcp = "/.config/gcloud" nocase
        $azure = "/.azure/credentials" nocase
        $env = "/proc/self/environ" nocase

    condition:
        any of them
}

rule command_injection_environment_manipulation {
    meta:
        description = "Detects manipulation of environment variables"
        severity = "high"
        category = "command_injection"

    strings:
        $ld_preload = "LD_PRELOAD" fullword ascii
        $ld_library = "LD_LIBRARY_PATH" fullword ascii
        $dyld = "DYLD_INSERT_LIBRARIES" fullword ascii

    condition:
        any of them
}

rule command_injection_sql_injection {
    meta:
        description = "Detects SQL injection in command arguments"
        severity = "critical"
        category = "command_injection"

    strings:
        $sql1 = "'; DROP TABLE" nocase
        $sql2 = "'; DROP DATABASE" nocase
        $sql3 = "' OR '1'='1" nocase
        $sql4 = "' OR 1=1--" nocase
        $sql5 = "UNION SELECT" nocase

    condition:
        any of them
}

rule command_injection_reverse_shell {
    meta:
        description = "Detects reverse shell patterns"
        severity = "critical"
        category = "command_injection"

    strings:
        $bash_tcp = "/dev/tcp/" nocase
        $bash_udp = "/dev/udp/" nocase
        // netcat must be the command itself, not "nc" inside rsync or sync, and its
        // flags must be in the same simple command. Flags are case-sensitive:
        // -c runs a program, -C only sends CRLF.
        $nc_exec = /\b(nc|ncat|netcat)\b[^\n;|&]*\s(-[a-z]*[ec]|--(sh-)?exec)\b/
        $nc_listen_lp = /\b(nc|ncat|netcat)\b[^\n;|&]*\s-[a-z]*l[a-z]*([^\n;|&]*\s-)?[a-z]*p/
        $nc_listen_pl = /\b(nc|ncat|netcat)\b[^\n;|&]*\s-[a-z]*p[a-z]*([^\n;|&]*\s-)?[a-z]*l/

    condition:
        any of them
}

rule command_injection_interpreter_reverse_shell {
    meta:
        description = "Reverse shell via socat, a scripting interpreter, or a named-pipe backpipe"
        severity = "critical"
        category = "command_injection"

    strings:
        // Each family needs two signals present together: a network primitive
        // AND a shell bound to it. Either alone is routine (a socket client, a
        // subprocess call), so the pairing is what marks a reverse shell.

        // gawk and zsh have their own network layers; both are rare in day-to-day use.
        $awk_inet = /\/inet\/(?:tcp|udp)\/[0-9]/
        $zsh_mod = "zsh/net/tcp"
        $zsh_ztcp = /\bztcp\b/

        // socat bridging a TCP address to EXEC:/SYSTEM: of a shell.
        $socat = /\bsocat\b/ nocase
        $socat_sh = /\b(?:exec|system):["']?(?:[\w.\/-]*\/)?(?:sh|bash|zsh|ash|dash|ksh|pwsh|powershell|cmd)\b/ nocase

        // python: a socket, plus a pty shell, or a connected socket handed to a
        // shell through dup2, a subprocess's std streams, or os.exec*/system.
        // Daemonizing also dup2's fds, but onto a file and without connecting,
        // so requiring connect() for those keeps it out.
        $py_sock = /import\s+socket|from\s+socket\s+import|socket\.socket\s*\(/
        $py_connect = /(?:\.connect|create_connection)\s*\(\s*\(/
        $py_dup = /dup2\s*\(\s*\w+\.fileno\s*\(\s*\)/
        $py_sub = /(?:subprocess\.(?:call|run|Popen)|\bos\.popen|\bpopen)\b[^\n]{0,160}\.fileno\s*\(\s*\)/
        $py_shexec = /(?:\w{1,12}\.(?:call|run|Popen)|os\.system|os\.execl|os\.execvp?e?|os\.execlp)\s*\(\s*(?:\[\s*)?["'](?:[\w.\/-]*\/)?(?:sh|bash|zsh|dash|ash)\b/
        $py_pty = /pty\.spawn\s*\(\s*["']?(?:\[\s*["'])?(?:[\w.\/-]*\/)?(?:sh|bash|zsh|dash|ash)\b/

        // perl: a socket, plus a std handle dup'd onto it, or exec/system/qx of a shell.
        $perl_sock = /\b(?:use\s+socket|IO::Socket|sockaddr_in|inet_aton)\b/ nocase
        $perl_dup = /open\s*\(\s*STD(?:IN|OUT|ERR)\s*,\s*["']?>&|->\s*fdopen\s*\(/
        $perl_exec = /\b(?:exec|system)\b[^\n]{0,20}(?:["'](?:[\w.\/-]*\/)?(?:sh|bash|zsh|dash|ash)\b|\$_\s+while)|\bqx[({\[\/<]/ nocase

        // php: fsockopen/stream_socket_client, plus a command-execution sink or backticks.
        $php_sock = /\b(?:fsockopen|stream_socket_client)\s*\(/ nocase
        $php_exec = /\b(?:exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`\n]+`/ nocase

        // ruby: a TCPSocket, plus exec/system/spawn of a shell, IO.popen, Open3,
        // or command substitution (`...` or %x{...}) running socket input.
        $ruby_sock = /\bTCPSocket\.(?:open|new)\b/ nocase
        $ruby_exec = /\b(?:exec|system|spawn)\b[^\n]{0,30}(?:\/bin\/|\b(?:sh|bash|zsh|dash)\b)|\bIO\.popen\b|\bOpen3\b|`[^`\n]*#\{|%x[{(\[<]/ nocase

        // node: the net module, plus a child_process shell spawn.
        $node_net = /require\s*\(\s*["']net["']\s*\)|\bnet\.(?:connect|createConnection|Socket)\b/ nocase
        $node_sh = /(?:spawnSync|spawn|execFileSync|execFile|execSync|exec)\s*\(\s*["'][^"'\n]{0,20}\b(?:sh|bash|zsh|dash|ash|ksh|cmd|powershell|pwsh)\b/ nocase

        // named-pipe backpipe: a fifo, a network tool, and an interactive shell.
        $fifo = /\b(?:mkfifo|mknod)\b/ nocase
        $net_prim = /\b(?:nc|ncat|netcat|telnet)\b|\/dev\/(?:tcp|udp)\/|openssl\s+s_client/ nocase
        $sh_bin = /(?:^|[\s|=&;(])(?:\/bin\/)?(?:sh|bash|zsh|dash|ash)\b\s*-?[a-z]*i/ nocase

    condition:
        $awk_inet
        or ($zsh_mod and $zsh_ztcp)
        or ($socat and $socat_sh)
        or ($py_sock and ($py_pty or ($py_connect and ($py_dup or $py_sub or $py_shexec))))
        or ($perl_sock and ($perl_dup or $perl_exec))
        or ($php_sock and $php_exec)
        or ($ruby_sock and $ruby_exec)
        or ($node_net and $node_sh)
        or ($fifo and $net_prim and $sh_bin)
}

rule command_injection_cron_manipulation {
    meta:
        description = "Detects cron job manipulation attempts"
        severity = "critical"
        category = "command_injection"

    strings:
        $crontab = /crontab\s+-[a-z]/ nocase
        $cron_dir = "/etc/cron" nocase
        $var_spool = "/var/spool/cron" nocase

    condition:
        any of them
}
