/*
 * Data Exfiltration Detection Rules
 */

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
        $azure1 = "/.azure/accessTokens.json"
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

rule data_exfiltration_dns_tunneling {
    meta:
        description = "Detects potential DNS tunneling"
        severity = "high"
        category = "exfiltration"

    strings:
        $tool1 = "dnscat"
        $tool2 = "iodine"
        $tool3 = "dns2tcp"

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

    condition:
        any of them
}
