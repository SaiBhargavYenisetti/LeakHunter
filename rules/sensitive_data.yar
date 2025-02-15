rule credit_card {
    strings:
        $cc1 = /[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}/  // Matches formatted CCs
        $cc2 = /[0-9]{13,16}/  // Matches unformatted CCs
    condition:
        any of them
}

rule email {
    strings:
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
    condition:
        $email
}

rule api_key {
    strings:
        $aws_access = /AKIA[0-9A-Z]{16}/
        $aws_secret = /[0-9a-zA-Z\/+]{40}/
        $google_key = /AIza[0-9A-Za-z\-_]{35}/
        $stripe_key = /sk_(live|test)_[0-9a-zA-Z]{24,}/
        $github_key = /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}/
        $generic_key = /[A-Za-z0-9_\-]{20,40}/
    condition:
        any of them
}

rule password {
    strings:
        $password1 = /password[=:][A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?]{4,}/
        $password2 = /passwd[=:][A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?]{4,}/
        $password3 = /pwd[=:][A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?]{4,}/
    condition:
        any of them
}