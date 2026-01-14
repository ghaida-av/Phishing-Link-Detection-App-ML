package com.example.phishinglinkdetector

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {

    // Change this to your backend server IP/URL
    // For emulator: use "10.0.2.2" instead of "localhost"
    // For physical device: use your computer's IP address on the same network
    private val BASE_URL = "http://10.0.2.2:5001"  // Emulator
    // private val BASE_URL = "http://YOUR_COMPUTER_IP:5001"  // Physical device

    private lateinit var linkInput: EditText
    private lateinit var checkBtn: Button
    private lateinit var resultText: TextView
    private lateinit var statusText: TextView
    private lateinit var intelText: TextView

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        linkInput = findViewById(R.id.linkInput)
        checkBtn = findViewById(R.id.checkBtn)
        resultText = findViewById(R.id.resultText)
        statusText = findViewById(R.id.statusText)
        intelText = findViewById(R.id.intelText)

        checkBtn.setOnClickListener {
            val input = linkInput.text.toString().trim()
            
            if (input.isEmpty()) {
                resultText.text = "Please enter a URL or email"
                statusText.text = ""
                return@setOnClickListener
            }

            checkUrl(input)
        }
    }

    private fun checkUrl(url: String) {
        resultText.text = "Checking..."
        statusText.text = ""
        intelText.text = ""
        checkBtn.isEnabled = false

        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    performApiCall(url)
                }

                withContext(Dispatchers.Main) {
                    displayResult(result)
                    checkBtn.isEnabled = true
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    resultText.text = "❌ Error: ${e.message}"
                    statusText.text = "Check your connection and server URL"
                    intelText.text = ""
                    checkBtn.isEnabled = true
                }
            }
        }
    }

    private fun performApiCall(url: String): ApiResponse {
        val json = JSONObject()
        json.put("url", url)

        val mediaType = "application/json; charset=utf-8".toMediaType()
        val requestBody = json.toString().toRequestBody(mediaType)

        val request = Request.Builder()
            .url("$BASE_URL/predict")
            .post(requestBody)
            .addHeader("Content-Type", "application/json")
            .build()

        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty response")

        if (!response.isSuccessful) {
            throw Exception("HTTP ${response.code}: $responseBody")
        }

        val jsonResponse = JSONObject(responseBody)

        // Parse high-level threat intel fields
        val threatIntel = jsonResponse.optJSONObject("threat_intel")

        var domainInfo: String? = null
        var blacklistInfo: String? = null

        if (threatIntel != null) {
            val whois = threatIntel.optJSONObject("whois")
            val flags = threatIntel.optJSONObject("flags")
            val gsb = threatIntel.optJSONObject("google_safe_browsing")
            val phish = threatIntel.optJSONObject("phishtank")

            // Domain age info
            if (whois != null && whois.optBoolean("success", false)) {
                val domain = whois.optString("domain", "")
                val ageDays = whois.optInt("age_days", -1)
                if (ageDays >= 0 && domain.isNotEmpty()) {
                    domainInfo = "Domain: $domain ($ageDays days old)"
                }
            }

            // Blacklist info
            val listed = flags?.optBoolean("listed_in_blacklist", false) ?: false
            if (listed) {
                val sources = mutableListOf<String>()
                if (phish != null && phish.optBoolean("enabled", false) &&
                    phish.optBoolean("verified_phish", false)
                ) {
                    sources.add("PhishTank")
                }
                if (gsb != null && gsb.optBoolean("enabled", false) &&
                    gsb.optBoolean("unsafe", false)
                ) {
                    sources.add("Google Safe Browsing")
                }
                val src = if (sources.isNotEmpty()) sources.joinToString(", ") else "blacklist"
                blacklistInfo = "Blacklist: flagged by $src"
            } else {
                blacklistInfo = "Blacklist: not flagged"
            }
        }

        return ApiResponse(
            verdict = jsonResponse.optString("verdict", "UNKNOWN"),
            urlType = jsonResponse.optString("url_type", "unknown"),
            confidence = jsonResponse.optDouble("confidence", 0.0),
            fromCache = jsonResponse.optBoolean("from_cache", false),
            message = jsonResponse.optString("message", ""),
            domainInfo = domainInfo,
            blacklistInfo = blacklistInfo
        )
    }

    private fun displayResult(result: ApiResponse) {
        when (result.verdict) {
            "PHISHING" -> {
                resultText.text = "⚠ PHISHING ${result.urlType.uppercase()}"
                resultText.setTextColor(getColor(android.R.color.holo_red_dark))
            }
            "SAFE" -> {
                resultText.text = "✅ SAFE ${result.urlType.uppercase()}"
                resultText.setTextColor(getColor(android.R.color.holo_green_dark))
            }
            "INVALID" -> {
                resultText.text = "❌ INVALID INPUT"
                resultText.setTextColor(getColor(android.R.color.darker_gray))
            }
            else -> {
                resultText.text = "❓ UNKNOWN"
                resultText.setTextColor(getColor(android.R.color.darker_gray))
            }
        }

        val cacheInfo = if (result.fromCache) " (from cache)" else ""
        val confidencePercent = (result.confidence * 100).toInt()
        statusText.text = "Confidence: $confidencePercent%$cacheInfo"

        val lines = mutableListOf<String>()
        result.domainInfo?.let { lines.add(it) }
        result.blacklistInfo?.let { lines.add(it) }
        intelText.text = lines.joinToString("\n")
    }

    data class ApiResponse(
        val verdict: String,
        val urlType: String,
        val confidence: Double,
        val fromCache: Boolean,
        val message: String,
        val domainInfo: String?,
        val blacklistInfo: String?
    )
}
