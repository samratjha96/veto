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
        $dsa = "-----BEGIN DSA PRIVATE KEY-----"
        $pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

    condition:
        any of them
}

rule secrets_gcp_credentials {
    meta:
        description = "Detects Google Cloud Platform credentials"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $gcp_sa1 = /"type"\s*:\s*"service_account"/
        $gcp_sa2 = /"private_key"/
        $gcp_key = /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/
        $gcp_api = /AIza[0-9A-Za-z_\-]{35}/
        $gcp_oauth = /"client_secret"\s*:\s*"[A-Za-z0-9_\-]{20,}"/

    condition:
        ($gcp_sa1 and $gcp_sa2) or $gcp_key or $gcp_api or $gcp_oauth
}

rule secrets_azure_credentials {
    meta:
        description = "Detects Microsoft Azure credentials"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $azure_storage = /DefaultEndpointsProtocol=https.*AccountKey=[A-Za-z0-9\/\+=]{88}/
        $azure_sp_id = /"appId"\s*:\s*"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"/
        $azure_sp_secret = /"password"\s*:\s*"[A-Za-z0-9~\.\-]{20,}"/
        $azure_sub = /Ocp-Apim-Subscription-Key['"\s]*[:=]['"\s]*[a-f0-9]{32}/ nocase

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
        $slack_webhook = /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/
        $slack_app = /xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]{64}/

    condition:
        any of them
}

rule secrets_stripe_keys {
    meta:
        description = "Detects Stripe API keys"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $stripe_secret = /sk_(test|live)_[0-9A-Za-z]{24,}/
        $stripe_restricted = /rk_(test|live)_[0-9A-Za-z]{24,}/

    condition:
        any of them
}

rule secrets_twilio_credentials {
    meta:
        description = "Detects Twilio API credentials"
        severity = "high"
        category = "secrets_detection"

    strings:
        $twilio_sid = /AC[a-f0-9]{32}/
        $twilio_token = /twilio[_-]?auth[_-]?token['"\s]*[:=]['"\s]*[a-f0-9]{32}/ nocase
        $twilio_key = /SK[a-f0-9]{32}/

    condition:
        any of them
}

rule secrets_sendgrid_keys {
    meta:
        description = "Detects SendGrid API keys"
        severity = "high"
        category = "secrets_detection"

    strings:
        $sendgrid = /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/

    condition:
        $sendgrid
}

rule secrets_jwt_tokens {
    meta:
        description = "Detects JWT tokens"
        severity = "high"
        category = "secrets_detection"

    strings:
        $jwt = /eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/

    condition:
        $jwt and filesize < 10KB
}

rule secrets_encryption_keys {
    meta:
        description = "Detects encryption keys and certificates"
        severity = "critical"
        category = "secrets_detection"

    strings:
        $aes256 = /aes[_-]?key['"\s]*[:=]['"\s]*[a-fA-F0-9]{64}/ nocase
        $aes128 = /aes[_-]?key['"\s]*[:=]['"\s]*[a-fA-F0-9]{32}/ nocase
        $base64_key = /encryption[_-]?key['"\s]*[:=]['"\s]*[A-Za-z0-9\/\+]{32,}==?/ nocase

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
