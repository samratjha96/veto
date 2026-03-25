/*
 * Secrets Detection Rules
 */

rule secrets_api_keys_generic {
    meta:
        description = "Detects generic API key patterns"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $api1 = /api[_-]?key['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase
        $api2 = /api[_-]?secret['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase
        $api3 = /api[_-]?token['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase
        $access1 = /access[_-]?key['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase
        $access2 = /secret[_-]?key['"\s]*[:=]['"\s]*[A-Za-z0-9_\-]{20,}/ nocase

    condition:
        any of them
}

rule secrets_aws_credentials {
    meta:
        description = "Detects AWS credentials"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $aws_key = /AKIA[0-9A-Z]{16}/
        $aws_secret = /aws_secret_access_key['"\s]*[:=]['"\s]*[A-Za-z0-9\/\+]{40}/ nocase
        $aws_token = /aws_session_token['"\s]*[:=]['"\s]*[A-Za-z0-9\/\+]{100,}/ nocase

    condition:
        any of them
}

rule secrets_private_keys {
    meta:
        description = "Detects private cryptographic keys"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $private = "-----BEGIN PRIVATE KEY-----"
        $encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"

    condition:
        any of them
}

rule secrets_github_tokens {
    meta:
        description = "Detects GitHub tokens"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $gh_pat = /ghp_[0-9A-Za-z]{36}/
        $gh_oauth = /gho_[0-9A-Za-z]{36}/
        $gh_server = /ghs_[0-9A-Za-z]{36}/

    condition:
        any of them
}

rule secrets_slack_tokens {
    meta:
        description = "Detects Slack tokens and webhooks"
        severity = "high"
        category = "secrets_detection"

    strings:
        $slack_bot = /xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/
        $slack_user = /xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/

    condition:
        any of them
}

rule secrets_database_credentials {
    meta:
        description = "Detects database connection strings"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $mongodb = /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/
        $postgres = /postgres(ql)?:\/\/[^:]+:[^@]+@/
        $mysql = /mysql:\/\/[^:]+:[^@]+@/
        $redis = /redis:\/\/:[^@]+@/

    condition:
        any of them
}

rule secrets_openai_keys {
    meta:
        description = "Detects OpenAI API keys"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $openai = /sk-[A-Za-z0-9]{48}/

    condition:
        any of them
}

rule secrets_anthropic_keys {
    meta:
        description = "Detects Anthropic API keys"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $anthropic = /sk-ant-[A-Za-z0-9_\-]{95,}/

    condition:
        $anthropic
}

rule secrets_generic_passwords {
    meta:
        description = "Detects generic password patterns in structured data"
        severity = "high"
        category = "secrets_detection"

    strings:
        $pass1 = /"password"\s*:\s*"[^\s"]{8,}"/ nocase
        $var1 = /PASSWORD\s*=\s*["'][^\s"']{8,}["']/
        $var2 = /SECRET\s*=\s*["'][^\s"']{8,}["']/

    condition:
        any of them
}
