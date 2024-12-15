rule DetectMaliciousScriptInPDF {
    meta:
        description = "Detects a PDF containing the text 'malicious_script'"
        author = "Kasthuri"
        date = "2024-09-28"
    
    strings:
        $js_function = "function("
        $eval = "eval("
        $malicious_js = "document.write(unescape("
    condition:
        $js_function or $eval or $malicious_js
}

rule DetectMaliciousURLs {
    meta:
        description = "Detects potentially malicious URLs in a PDF"
        author = "Kasthuri"
        date = "2024-09-28"
    
    strings:
        $obfuscated_url = /%[0-9A-Fa-f]{2}/
        $base64_encoded_url = /[a-zA-Z0-9+\/=]{20,}/
        $phishing_url = /example\.com.*example\.com|example\.com.*secure|paypal\.com.*login/
        $url_shortener = /bit\.ly|tinyurl\.com|goo\.gl/
        $suspicious_extension = /\.exe|\.php\.exe|\.js\.exe/
        $redirect_chain = /redirect\?url=/
        $suspicious_path = /admin|config|login|wp-admin/

    condition:
        $obfuscated_url or $base64_encoded_url or $phishing_url or $url_shortener or $suspicious_extension or $redirect_chain or $suspicious_path
}
