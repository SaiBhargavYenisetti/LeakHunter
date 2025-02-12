rule credit_card {
    strings:
        $cc = /\b(?:\d[ -]*?){13,16}\b/
    condition:
        $cc
}

rule email {
    strings:
        $email = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/
    condition:
        $email
}

rule api_key {
    strings:
        $api_key = /(?i)(?:api_key|apikey|aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,})["']?/
    condition:
        $api_key
}

rule password {
    strings:
        $password = /(?i)(?:password|passwd|pwd)\s*[=:]\s*["']?([A-Za-z0-9@#$%^&+=]{4,})["']?/
    condition:
        $password
}