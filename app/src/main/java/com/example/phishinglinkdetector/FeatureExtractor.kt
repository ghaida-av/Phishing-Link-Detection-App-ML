package com.example.phishinglinkdetector

import java.net.URL
import java.util.regex.Pattern

/**
 * Feature extraction for URL phishing detection
 * Matches the Python feature extraction logic
 */
object FeatureExtractor {
    
    private val SUSPICIOUS_KEYWORDS = listOf(
        "login", "verify", "bank", "secure", "account",
        "update", "confirm", "suspend", "click", "here",
        "free", "win", "prize", "urgent", "limited"
    )
    
    private val SUSPICIOUS_TLDS = listOf(".tk", ".ml", ".ga", ".cf", ".gq")
    
    private val COMMON_DOMAINS = listOf(
        "google", "facebook", "amazon", "microsoft", "apple", "paypal"
    )
    
    private val IP_PATTERN = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")
    
    /**
     * Extract 26 features from URL (matching Python implementation)
     */
    fun extractFeatures(url: String): FloatArray {
        val features = mutableListOf<Float>()
        val urlLower = url.lowercase()
        
        // Basic URL features (10 features)
        features.add(url.length.toFloat())
        features.add(url.count { it == '.' }.toFloat())
        features.add(url.count { it == '-' }.toFloat())
        features.add(url.count { it == '_' }.toFloat())
        features.add(url.count { it == '/' }.toFloat())
        features.add(url.count { it == '?' }.toFloat())
        features.add(url.count { it == '=' }.toFloat())
        features.add(url.count { it == '@' }.toFloat())
        features.add(url.count { it == '&' }.toFloat())
        
        // Protocol features (3 features)
        features.add(if (url.startsWith("https://")) 1f else 0f)
        features.add(if (url.startsWith("http://")) 1f else 0f)
        features.add(if ("https" in urlLower) 1f else 0f)
        
        // Suspicious keywords count (1 feature)
        val keywordCount = SUSPICIOUS_KEYWORDS.count { it in urlLower }
        features.add(keywordCount.toFloat())
        
        // Domain features (5 features)
        try {
            val normalizedUrl = if ("://" in url) url else "http://$url"
            val parsedUrl = URL(normalizedUrl)
            val domain = parsedUrl.host ?: parsedUrl.path.split("/").first()
            
            features.add(domain.length.toFloat())
            features.add(domain.count { it == '.' }.toFloat())
            
            // IP address check
            features.add(if (IP_PATTERN.matcher(domain).find()) 1f else 0f)
            
            // Suspicious TLD check
            val hasSuspiciousTld = SUSPICIOUS_TLDS.any { it in domain.lowercase() }
            features.add(if (hasSuspiciousTld) 1f else 0f)
            
            // Common domain check (typosquatting)
            val hasCommonDomain = COMMON_DOMAINS.any { it in domain.lowercase() }
            features.add(if (hasCommonDomain) 1f else 0f)
        } catch (e: Exception) {
            features.addAll(listOf(0f, 0f, 0f, 0f, 0f))
        }
        
        // Path features (2 features)
        try {
            val normalizedUrl = if ("://" in url) url else "http://$url"
            val parsedUrl = URL(normalizedUrl)
            val path = parsedUrl.path
            
            features.add(path.length.toFloat())
            features.add(path.count { it == '/' }.toFloat())
        } catch (e: Exception) {
            features.addAll(listOf(0f, 0f))
        }
        
        // Query string features (2 features)
        try {
            val normalizedUrl = if ("://" in url) url else "http://$url"
            val parsedUrl = URL(normalizedUrl)
            val query = parsedUrl.query ?: ""
            
            features.add(query.length.toFloat())
            features.add(query.count { it == '&' }.toFloat())
        } catch (e: Exception) {
            features.addAll(listOf(0f, 0f))
        }
        
        // Port number check (1 feature)
        try {
            val normalizedUrl = if ("://" in url) url else "http://$url"
            val parsedUrl = URL(normalizedUrl)
            val port = parsedUrl.port
            val hasNonStandardPort = port != -1 && port !in listOf(80, 443)
            features.add(if (hasNonStandardPort) 1f else 0f)
        } catch (e: Exception) {
            features.add(0f)
        }
        
        // Digit ratio (1 feature)
        val digitCount = url.count { it.isDigit() }
        features.add(if (url.isNotEmpty()) digitCount.toFloat() / url.length else 0f)
        
        // Letter ratio (1 feature)
        val letterCount = url.count { it.isLetter() }
        features.add(if (url.isNotEmpty()) letterCount.toFloat() / url.length else 0f)
        
        return features.toFloatArray()
    }
}
