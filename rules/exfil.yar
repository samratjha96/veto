/*
 * Data Exfiltration Detection Rules
 */

rule data_exfiltration_sensitive_files {
    meta:
        description = "Detects access to sensitive credential and configuration files"
        severity = "critical"
        category = "credential_access"

    strings:
        // SSH keys
        $ssh1 = "/.ssh/id_rsa"
        $ssh2 = "/.ssh/id_ed25519"
        $ssh3 = "/.ssh/id_ecdsa"

        // Certificate files
        $cert1 = ".pfx"
        $cert2 = ".p12"

        // Database credentials
        $db1 = ".my.cnf"
        $db2 = ".pgpass"

    condition:
        any of them
}

rule data_exfiltration_cloud_credentials {
    meta:
        description = "Detects access to sensitive cloud credentials"
        severity = "critical"
        category = "credential_access"

    strings:
        $aws1 = "/.aws/credentials"
        $aws2 = "aws_access_key_id"
        $aws3 = "aws_secret_access_key"
        $gcp1 = "/.config/gcloud/application_default_credentials.json"
        $gcp2 = "/.config/gcloud/credentials.db"
        $gcp3 = "service-account.json"
        $azure1 = "/.azure/accessTokens.json"
        $azure2 = "/.azure/msal_token_cache.json"
        $oci1 = "/.oci/oci_api_key.pem"
        $k8s1 = "/.kube/config"

    condition:
        any of them
}

rule data_exfiltration_paste_sites {
    meta:
        description = "Detects attempts to send data to paste services"
        severity = "high"
        category = "exfiltration"

    strings:
        $paste1 = "pastebin.com"
        $paste2 = "paste.ee"
        $paste3 = "hastebin.com"
        $paste4 = "gist.github.com"
        $paste5 = "privatebin.net"
        $paste6 = "rentry.co"

    condition:
        any of them
}

rule data_exfiltration_external_domains {
    meta:
        description = "Detects suspicious external domain references for data exfiltration"
        severity = "high"
        category = "exfiltration"

    strings:
        $webhook1 = "webhook.site"
        $webhook2 = "requestbin.com"
        $webhook3 = "pipedream.com"
        $discord = "discord.com/api/webhooks/"
        $tunnel1 = "ngrok.io"
        $tunnel2 = "localtunnel.me"

    condition:
        any of them
}

rule data_exfiltration_network_commands {
    meta:
        description = "Detects network commands commonly used for data exfiltration"
        severity = "high"
        category = "exfiltration"

    strings:
        $curl1 = /curl\s+-[A-Za-z]*d\s+/
        $curl2 = /curl\s+--data\s+/
        $curl3 = /curl\s+-[A-Za-z]*F\s+/
        $curl4 = /curl\s+-T\s+/
        $wget1 = /wget\s+--post-data/
        $wget2 = /wget\s+--post-file/

    condition:
        any of them
}

rule data_exfiltration_file_read_with_send {
    meta:
        description = "Detects patterns of reading files and sending data"
        severity = "critical"
        category = "exfiltration"

    strings:
        $pattern1 = /cat\s+[\w\/.]+\s*\|\s*(curl|wget)/
        $pattern2 = /cat\s+[\w\/.]+\s*>\s*\/dev\/tcp/
        $exfil1 = /exfiltrate\s+(data|file)/i
        $exfil2 = /send\s+(file|data)\s+to\s+http/i

    condition:
        any of them
}

rule data_exfiltration_encoding_patterns {
    meta:
        description = "Detects encoding patterns commonly used for data exfiltration"
        severity = "medium"
        category = "exfiltration"

    strings:
        $b64_1 = /base64\s+(encode|encoding)/i
        $b64_2 = /btoa\(/
        $b64_3 = /\.encode\('base64'\)/
        $compress_1 = /zip\s+(and\s+)?(send|upload|post)/i

    condition:
        any of them
}

rule data_exfiltration_dns_tunneling {
    meta:
        description = "Detects potential DNS tunneling"
        severity = "high"
        category = "exfiltration"

    strings:
        $tool1 = "dnscat"
        $tool2 = "iodine"
        $tool3 = "dns2tcp"

        // Suspicious DNS queries with long hex payloads
        $dns1 = /nslookup\s+[a-f0-9]{32,}/
        $dns2 = /dig\s+[a-f0-9]{32,}/

        // Long subdomain labels (common in DNS tunneling)
        $long_label = /[a-z0-9]{50,}\.[a-z0-9]+\.[a-z]{2,}/

    condition:
        any of them
}

rule data_exfiltration_steganography {
    meta:
        description = "Detects potential steganography techniques"
        severity = "medium"
        category = "exfiltration"

    strings:
        $tool1 = "steghide"
        $tool2 = "outguess"
        $tool3 = "stegsnow"
        $cmd1 = /embed\s+(data|message)\s+in\s+(image|audio|video)/i
        $cmd2 = /hide\s+(data|message)\s+in\s+(image|audio|video)/i

    condition:
        any of them
}

rule data_exfiltration_memory_dump {
    meta:
        description = "Detects attempts to dump memory or process information"
        severity = "high"
        category = "credential_access"

    strings:
        $dump1 = /dump\s+(memory|process|credentials)/i
        $dump2 = "memdump"
        $dump3 = "procdump"
        $linux1 = "/proc/self/mem"
        $linux2 = "/proc/self/maps"
        $linux3 = "gcore"
        $env_dump1 = "env | grep"
        $env_dump2 = "printenv"
        $env_dump3 = "export -p"

    condition:
        any of them
}
