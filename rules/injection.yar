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
        $nc_listen = /nc.*-[a-z]*l.*-[a-z]*p/ nocase
        $nc_exec = /nc.*-[a-z]*e/ nocase

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
