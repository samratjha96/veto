/*
 * Destructive operations (sane defaults)
 *
 * Catches common CLI patterns that remove workloads, data, or infrastructure.
 */

rule destructive_docker_podman {
    meta:
        description = "Container CLI: remove images, containers, volumes, or aggressive prune"
        severity = "high"
        category = "destructive_ops"

    strings:
        $d1 = /docker\s+rm(\s|$)/ nocase
        $d2 = /docker\s+rmi(\s|$)/ nocase
        $d3 = /docker\s+container\s+rm(\s|$)/ nocase
        $d4 = /docker\s+volume\s+rm(\s|$)/ nocase
        $d5 = /docker\s+network\s+rm(\s|$)/ nocase
        $d6 = /docker\s+system\s+prune(\s|$)/ nocase
        $d7 = /docker\s+compose\s+down(\s|$)/ nocase
        $d8 = /docker-compose\s+down(\s|$)/ nocase
        $d9 = /docker\s+swarm\s+leave(\s|$)/ nocase

        $p1 = /podman\s+rm(\s|$)/ nocase
        $p2 = /podman\s+rmi(\s|$)/ nocase
        $p3 = /podman\s+volume\s+rm(\s|$)/ nocase
        $p4 = /podman\s+system\s+prune(\s|$)/ nocase

    condition:
        any of them
}

rule destructive_kubernetes {
    meta:
        description = "kubectl/k8s: delete resources, drain nodes"
        severity = "high"
        category = "destructive_ops"

    strings:
        $k1 = /kubectl\s+delete(\s|$)/ nocase
        $k2 = /kubectl\s+drain(\s|$)/ nocase
        $k3 = /kubectl\s+replace\s+--force/ nocase
        $k4 = /helm\s+uninstall(\s|$)/ nocase
        $k5 = /helm\s+delete(\s|$)/ nocase

    condition:
        any of them
}

rule destructive_terraform_iac {
    meta:
        description = "IaC: destroy or replace-all style applies"
        severity = "high"
        category = "destructive_ops"

    strings:
        $t1 = /terraform\s+destroy(\s|$)/ nocase
        $t2 = /terraform\s+apply[^;\n]*-destroy/ nocase
        $t3 = /pulumi\s+destroy(\s|$)/ nocase
        $t4 = /cdk\s+destroy(\s|$)/ nocase

    condition:
        any of them
}

rule destructive_cloud_cli {
    meta:
        description = "Cloud CLIs: terminate VMs, drop buckets, delete DBs"
        severity = "high"
        category = "destructive_ops"

    strings:
        $a1 = /aws\s+ec2\s+terminate-instances(\s|$)/ nocase
        $a2 = /aws\s+s3\s+rb(\s|$)/ nocase
        $a3 = /aws\s+rds\s+delete-db-instance(\s|$)/ nocase

        $g1 = /gcloud\s+compute\s+instances\s+delete(\s|$)/ nocase
        $g2 = /gcloud\s+sql\s+instances\s+delete(\s|$)/ nocase
        $g3 = /gcloud\s+projects\s+delete(\s|$)/ nocase

        $z1 = /az\s+(vm|disk|group|storage\s+account)\s+delete(\s|$)/ nocase

    condition:
        any of them
}

rule destructive_database_admin {
    meta:
        description = "Database CLIs: flush all data or drop server/DB from shell"
        severity = "high"
        category = "destructive_ops"

    strings:
        $r1 = /redis-cli(\s+[^\n]*)?\s+FLUSHALL/ nocase
        $r2 = /redis-cli(\s+[^\n]*)?\s+FLUSHDB/ nocase
        $m1 = /mongosh[^\n]*dropDatabase/ nocase
        $pg1 = /dropdb(\s|$)/ nocase

    condition:
        any of them
}

rule destructive_git_force {
    meta:
        description = "Git: force-push or hard reset"
        severity = "high"
        category = "destructive_ops"

    strings:
        $g1 = /git\s+push[^\n]*--force/ nocase
        $g2 = /git\s+push\s+-f(\s|$)/ nocase
        $g3 = /git\s+reset\s+--hard/ nocase
        $g4 = /git\s+filter-branch/ nocase

    condition:
        any of them
}

rule destructive_recursive_rm {
    meta:
        description = "Recursive+force rm (-rf/-fr): chained or bare"
        severity = "high"
        category = "destructive_ops"

    strings:
        $a = /&&\s*(?:sudo\s+)?rm\s+-(?:[a-z0-9]*r[a-z0-9]*f|[a-z0-9]*f[a-z0-9]*r)[a-z0-9]*\b/ nocase
        $b = /;\s*(?:sudo\s+)?rm\s+-(?:[a-z0-9]*r[a-z0-9]*f|[a-z0-9]*f[a-z0-9]*r)[a-z0-9]*\b/ nocase
        $c = /\|\s*(?:sudo\s+)?rm\s+-(?:[a-z0-9]*r[a-z0-9]*f|[a-z0-9]*f[a-z0-9]*r)[a-z0-9]*\b/ nocase
        $d = /\|\|\s*(?:sudo\s+)?rm\s+-(?:[a-z0-9]*r[a-z0-9]*f|[a-z0-9]*f[a-z0-9]*r)[a-z0-9]*\b/ nocase
        $bare = /\brm\s+-(?:[a-z0-9]*r[a-z0-9]*f|[a-z0-9]*f[a-z0-9]*r)[a-z0-9]*\b/ nocase
        $sudo_bare = /\bsudo\s+rm\s+-(?:[a-z0-9]*r[a-z0-9]*f|[a-z0-9]*f[a-z0-9]*r)[a-z0-9]*\b/ nocase
        $line_start = /(?:^|\n)\s*(?:sudo\s+)?rm\s+-(?:[a-z0-9]*r[a-z0-9]*f|[a-z0-9]*f[a-z0-9]*r)[a-z0-9]*\b/ nocase

    condition:
        any of ($a, $b, $c, $d, $bare, $sudo_bare, $line_start)
}

rule destructive_filesystem_disk {
    meta:
        description = "Disk / FS: mkfs, wipe block devices, chmod 777 on root"
        severity = "high"
        category = "destructive_ops"

    strings:
        $f1 = /mkfs\./ nocase
        $f2 = /\bdd\s+if=/ nocase
        $f3 = /shred\s+-/ nocase
        $f4 = "rm -rf /" nocase
        $f5 = "rm -fr /" nocase
        $f6 = /chmod\s+-R\s+777\s+\// nocase

    condition:
        any of them
}

rule destructive_system_power {
    meta:
        description = "System halt / poweroff"
        severity = "high"
        category = "destructive_ops"

    strings:
        $s1 = /shutdown\s+(-h|-r|P|now)/ nocase
        $s2 = /\bpoweroff(\s|$)/ nocase
        $s3 = /\bhalt(\s|$)/ nocase
        $s4 = /systemctl\s+(poweroff|halt)(\s|$)/ nocase

    condition:
        any of them
}
