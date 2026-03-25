/*
 * Obfuscation Detection Rules
 *
 * Detects encoding and obfuscation techniques:
 * - Base64 encoding of commands
 * - Hex encoding
 * - URL encoding / double encoding
 * - Unicode homoglyphs
 * - HTML/XML entity encoding
 * - ROT13 / Caesar cipher
 * - String concatenation tricks
 * - Encoding+execution combos
 */

rule obfuscation_base64_encoded_commands {
    meta:
        description = "Detects base64 encoded shell commands and suspicious strings"
        severity = "high"
        category = "obfuscation"

    strings:
        // Base64 encoded common commands
        $b64_bash = "YmFzaA==" // "bash"
        $b64_curl = "Y3VybA==" // "curl"
        $b64_wget = "d2dldA==" // "wget"
        $b64_eval = "ZXZhbA==" // "eval"
        $b64_chmod = "Y2htb2Q=" // "chmod"

        // Base64 encoded path traversal
        $b64_dotdot = "Li4v" // "../"
        $b64_etc = "L2V0Yy8=" // "/etc/"

        // Base64 encoded SQL injection
        $b64_drop = "RFJPUCBUQUJMRQ==" // "DROP TABLE"
        $b64_union = "VU5JT04gU0VMRUNU" // "UNION SELECT"

        // Long base64 strings (potential encoded payloads)
        $long_b64 = /[A-Za-z0-9+\/]{100,}={0,2}/

    condition:
        any of ($b64_*) or $long_b64
}

rule obfuscation_hex_encoding {
    meta:
        description = "Detects hex encoded commands and strings"
        severity = "high"
        category = "obfuscation"

    strings:
        // Hex encoded commands
        $hex_bash = /\\x62\\x61\\x73\\x68/ // bash
        $hex_curl = /\\x63\\x75\\x72\\x6c/ // curl
        $hex_eval = /\\x65\\x76\\x61\\x6c/ // eval

        // URL hex encoding for path traversal
        $url_hex1 = /%2[eE]%2[eE]%2[fF]/ // ../

        // Long hex string sequences
        $hex_long = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/

        // 0x prefix hex arrays
        $hex_prefix = /0x[0-9a-fA-F]{2}([,\s]+0x[0-9a-fA-F]{2}){10,}/

    condition:
        any of them
}

rule obfuscation_html_entity_encoding {
    meta:
        description = "Detects HTML/XML entity encoding for obfuscation"
        severity = "high"
        category = "obfuscation"

    strings:
        // Encoded dangerous patterns
        $entity_script = "&#115;&#99;&#114;&#105;&#112;&#116;" // "script"
        $entity_bash = "&#98;&#97;&#115;&#104;" // "bash"
        $entity_eval = "&#101;&#118;&#97;&#108;" // "eval"

        // Long chains of numeric HTML entities
        $entity_chain = /&#[0-9]{2,3};(&#[0-9]{2,3};){7,}/

        // Long chains of hex HTML entities
        $unicode_entity = /&#x[0-9a-fA-F]{2,4};(&#x[0-9a-fA-F]{2,4};){7,}/

    condition:
        any of them
}

rule obfuscation_url_encoding {
    meta:
        description = "Detects excessive URL encoding for obfuscation"
        severity = "medium"
        category = "obfuscation"

    strings:
        // Double URL encoding
        $double_encode = /%25[0-9a-fA-F]{2}/

        // URL encoded commands
        $url_bash = "%62%61%73%68" // bash
        $url_curl = "%63%75%72%6c" // curl
        $url_script = "%73%63%72%69%70%74" // script

        // Excessive URL encoding (10+ encoded chars in sequence)
        $url_chain = /(%[0-9a-fA-F]{2}){10,}/

    condition:
        any of them
}

rule obfuscation_rot13_encoding {
    meta:
        description = "Detects ROT13 or Caesar cipher encoding"
        severity = "low"
        category = "obfuscation"

    strings:
        // ROT13 encoded common words
        $rot13_bash = "onfpu" // "bash" in ROT13
        $rot13_curl = "phey" // "curl" in ROT13
        $rot13_eval = "riny" // "eval" in ROT13
        $rot13_exec = "rkrp" // "exec" in ROT13

    condition:
        any of them
}

rule obfuscation_json_escape_sequences {
    meta:
        description = "Detects excessive JSON/Unicode escape sequences for obfuscation"
        severity = "medium"
        category = "obfuscation"

    strings:
        // Long sequences of Unicode escapes
        $unicode_escape = /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){5,}/

        // Long sequences of escape chars
        $mixed_escape = /\\[nrtbf\\\/](\\[nrtbf\\\/]){10,}/

    condition:
        any of them
}

rule obfuscation_polyglot_file {
    meta:
        description = "Detects polyglot file indicators (multiple file types in one)"
        severity = "high"
        category = "obfuscation"

    strings:
        // PDF + executable
        $pdf_exec = "%PDF"
        $pdf_exec2 = "MZ"

        // Image + script
        $img_script = /\xFF\xD8\xFF/
        $img_script2 = "<script>"

        // ZIP + script
        $zip_script = "PK\x03\x04"
        $zip_script2 = "eval("

    condition:
        ($pdf_exec and $pdf_exec2) or
        ($img_script and $img_script2) or
        ($zip_script and $zip_script2)
}

rule obfuscation_encoding_with_execution {
    meta:
        description = "Detects decode functions combined with execution — strong obfuscation signal"
        severity = "high"
        category = "obfuscation"

    strings:
        // Decode functions
        $b64_decode = /base64\s*-d/
        $b64_decode2 = "atob("
        $b64_decode3 = "base64_decode("
        $url_decode = "urldecode("
        $url_decode2 = "decodeURIComponent("
        $hex_decode = "unhexlify("
        $hex_decode2 = "hex2bin("

        // Execution functions
        $eval = "eval"
        $exec = "exec"
        $system = "system"

    condition:
        ($b64_decode or $b64_decode2 or $b64_decode3 or $url_decode
        or $url_decode2 or $hex_decode or $hex_decode2) and
        ($eval or $exec or $system)
}
