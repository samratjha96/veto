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
