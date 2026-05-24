rule Cleartext_Credentials
{
    meta:
        description = "Detect common clear-text credential patterns"
        author = "packet-2"
    strings:
        $s1 = /password\s*[:=]\s*\"?[^&\s\"']{4,}/ nocase
        $s2 = /(passwd|pwd)\s*[:=]\s*\"?[^&\s\"']{4,}/ nocase
        $s3 = /\"?(api[_-]?key|secret|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?id)\"?\s*[:=]\s*\"?[A-Za-z0-9._\-]{6,}/ nocase
        $s4 = /authorization:\s*basic\s+[A-Za-z0-9+\/]{8,}={0,2}/ nocase
        $s5 = /bearer\s+[A-Za-z0-9_\-\.]{12,}/ nocase
        $s6 = /(otp|one[-_ ]?time[-_ ]?password|verification[_-]?code)\s*[:=]\s*\d{4,8}/ nocase
        $s7 = /(user(name)?|login)\s*[:=]\s*\"?[A-Za-z0-9._\-]{2,}/ nocase
        $s8 = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/
        $s9 = /\"?email\"?\s*[:=]\s*\"?[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/ nocase
        $s10 = /\"?phone\"?\s*[:=]\s*\"?\+?\d[\d\-\s]{7,}\d/ nocase
        $s11 = /\"?name\"?\s*[:=]\s*\"?[A-Za-z]{2,}\s+[A-Za-z]{2,}/ nocase
        $s12 = /\"?address\"?\s*[:=]\s*\"?[^\r\n\"']{6,}/ nocase
        $s13 = /tok_[A-Za-z0-9]{6,}/ nocase
    condition:
        any of them
}
