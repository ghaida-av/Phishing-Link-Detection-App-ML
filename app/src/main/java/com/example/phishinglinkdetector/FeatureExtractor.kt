package com.example.phishinglinkdetector

import java.net.URL
import java.util.regex.Pattern

/**
 * Feature extraction for URL phishing detection
 * Beginner-friendly version:
 * - Clear steps
 * - Small helper functions
 * - Same output/features as before
 */
object FeatureExtractor {

    private val SUSPICIOUS_KEYWORDS = listOf(
        "login", "verify", "bank", "secure", "account",
        "update", "confirm", "suspend", "click", "here",
        "free", "win", "prize", "urgent", "limited",
        "password", "reset", "unlock", "activate", "validate",
        "security", "alert", "warning", "expired", "locked"
    )

    private val SUSPICIOUS_TLDS = listOf(".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click")

    private val COMMON_DOMAINS = listOf(
        "google", "facebook", "amazon", "microsoft", "apple", "paypal",
        "netflix", "twitter", "instagram", "linkedin", "ebay", "yahoo"
    )

    private val TYPOSQUATTING_PATTERNS = listOf(
        "go0gle", "g00gle", "faceb00k", "amaz0n", "micr0soft",
        "paypa1", "app1e", "tw1tter", "1nstagram"
    )

    private val IP_PATTERN = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")

    private fun countChar(text: String, ch: Char): Int {
        return text.count { it == ch }
    }

    private fun normalizeToUrl(input: String): String {
        // URL(...) needs a protocol. If missing, add http:// like the Python code.
        return if ("://" in input) input else "http://$input"
    }

    /**
     * Extract 32 features from URL (enhanced phishing detection)
     */
    fun extractFeatures(url: String): FloatArray {
        val features = ArrayList<Float>(32)

        val urlLower = url.lowercase()

        // -------- 1) Basic URL features (9) --------
        features.add(url.length.toFloat())
        features.add(countChar(url, '.').toFloat())
        features.add(countChar(url, '-').toFloat())
        features.add(countChar(url, '_').toFloat())
        features.add(countChar(url, '/').toFloat())
        features.add(countChar(url, '?').toFloat())
        features.add(countChar(url, '=').toFloat())
        features.add(countChar(url, '@').toFloat())
        features.add(countChar(url, '&').toFloat())

        // -------- 2) Protocol features (3) --------
        features.add(if (url.startsWith("https://")) 1f else 0f)
        features.add(if (url.startsWith("http://")) 1f else 0f)
        features.add(if (urlLower.contains("https")) 1f else 0f)

        // -------- 3) Keyword feature (1) --------
        val keywordCount = SUSPICIOUS_KEYWORDS.count { keyword -> urlLower.contains(keyword) }
        features.add(keywordCount.toFloat())

        // -------- 4) Extra phishing pattern features (3) --------
        val urlShorteners = listOf("bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly")
        val hasShortener = urlShorteners.any { shortDomain -> urlLower.contains(shortDomain) }
        features.add(if (hasShortener) 1f else 0f)

        val hyphenCount = countChar(url, '-')
        val hasMultipleSuspicious = keywordCount > 2 && hyphenCount > 2
        features.add(if (hasMultipleSuspicious) 1f else 0f)

        val suspiciousPathParts = listOf("/login", "/verify", "/secure", "/account", "/update")
        val hasSuspiciousPath = try {
            val parsed = URL(normalizeToUrl(url))
            val pathLower = parsed.path.lowercase()
            suspiciousPathParts.any { part -> pathLower.contains(part) }
        } catch (_: Exception) {
            false
        }
        features.add(if (hasSuspiciousPath) 1f else 0f)

        // -------- 5) Domain features (8) --------
        try {
            val parsed = URL(normalizeToUrl(url))
            val domain = parsed.host.ifEmpty { parsed.path.split("/").firstOrNull().orEmpty() }
            val domainLower = domain.lowercase()

            features.add(domain.length.toFloat())
            features.add(countChar(domain, '.').toFloat())

            val hasIp = IP_PATTERN.matcher(domain).find()
            features.add(if (hasIp) 1f else 0f)

            val hasSuspiciousTld = SUSPICIOUS_TLDS.any { tld -> domainLower.contains(tld) }
            features.add(if (hasSuspiciousTld) 1f else 0f)

            val hasCommonDomain = COMMON_DOMAINS.any { brand -> domainLower.contains(brand) }
            features.add(if (hasCommonDomain) 1f else 0f)

            val hasTypo = TYPOSQUATTING_PATTERNS.any { typo -> domainLower.contains(typo) }
            features.add(if (hasTypo) 1f else 0f)

            val dotCount = countChar(domain, '.')
            val subdomainCount = dotCount - 1
            features.add(if (subdomainCount > 2) 1f else 0f)

            features.add(if (domain.contains('-')) 1f else 0f)
        } catch (_: Exception) {
            // If parsing fails, push zeros for all 8 domain features
            repeat(8) { features.add(0f) }
        }

        // -------- 6) Path features (2) --------
        try {
            val parsed = URL(normalizeToUrl(url))
            val path = parsed.path
            features.add(path.length.toFloat())
            features.add(countChar(path, '/').toFloat())
        } catch (_: Exception) {
            features.add(0f)
            features.add(0f)
        }

        // -------- 7) Query features (2) --------
        try {
            val parsed = URL(normalizeToUrl(url))
            val query = parsed.query ?: ""
            features.add(query.length.toFloat())
            features.add(countChar(query, '&').toFloat())
        } catch (_: Exception) {
            features.add(0f)
            features.add(0f)
        }

        // -------- 8) Port feature (1) --------
        try {
            val parsed = URL(normalizeToUrl(url))
            val port = parsed.port
            val isNonStandardPort = port != -1 && port !in listOf(80, 443)
            features.add(if (isNonStandardPort) 1f else 0f)
        } catch (_: Exception) {
            features.add(0f)
        }

        // -------- 9) Character ratio features (2) --------
        val digitCount = url.count { it.isDigit() }
        val letterCount = url.count { it.isLetter() }
        val length = url.length.coerceAtLeast(1)

        features.add(digitCount.toFloat() / length)
        features.add(letterCount.toFloat() / length)

        return features.toFloatArray()
    }
}
