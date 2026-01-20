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

    private val burl = "http://10.0.2.2:5001"  //emulator
    // private val burl = "http://****_IP:5001"  // Physical device

    private lateinit var link: EditText
    private lateinit var check: Button
    private lateinit var result: TextView
    private lateinit var status: TextView
    private lateinit var intel: TextView

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        link = findViewById(R.id.link)
        check = findViewById(R.id.check)
        result = findViewById(R.id.result)
        status = findViewById(R.id.status)
        intel = findViewById(R.id.intel)

        check.setOnClickListener {
            val input = link.text.toString().trim()
            
            if (input.isEmpty()) {
                result.text = "Please enter a URL or email"
                status.text = ""
                return@setOnClickListener
            }

            checkUrl(input)
        }
    }

    private fun checkUrl(url: String) {
        result.text = "Checking..."
        status.text = ""
        intel.text = ""
        check.isEnabled = false

        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    performApiCall(url)
                }

                withContext(Dispatchers.Main) {
                    displayResult(result)
                    check.isEnabled = true
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    result.text = "❌ Error: ${e.message}"
                    status.text = "Check your connection and server URL"
                    intel.text = ""
                    check.isEnabled = true
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

        //  high-level threat intel 
        val threatIntel = jsonResponse.optJSONObject("threat_intel")

        var domainInfo: String? = null
        var blacklistInfo: String? = null

        if (threatIntel != null) {
            val whois = threatIntel.optJSONObject("whois")
            val flags = threatIntel.optJSONObject("flags")
            val gsb = threatIntel.optJSONObject("google_safe_browsing")
            val phish = threatIntel.optJSONObject("phishtank")

            // Domain age 
            if (whois != null && whois.optBoolean("success", false)) {
                val domain = whois.optString("domain", "")
                val ageDays = whois.optInt("age_days", -1)
                if (ageDays >= 0 && domain.isNotEmpty()) {
                    domn = "Domain: $domain ($ageDays days old)"
                }
            }

            // Blacklist 
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
                blacklist = "Blacklist: flagged by $src"
            } else {
                blacklist = "Blacklist: not flagged"
            }
        }

        return ApiResponse(
            verdict = jsonResponse.optString("verdict", "UNKNOWN"),
            urlType = jsonResponse.optString("url_type", "unknown"),
            confidence = jsonResponse.optDouble("confidence", 0.0),
            fromCache = jsonResponse.optBoolean("from_cache", false),
            message = jsonResponse.optString("message", ""),
            domn = domn,
            blacklist = blacklist
        )
    }

    private fun displayResult(result: ApiResponse) {
        when (result.verdict) {
            "PHISHING" -> {
                result.text = "⚠ PHISHING ${result.urlType.uppercase()}"
                result.setTextColor(getColor(android.R.color.holo_red_dark))
            }
            "SAFE" -> {
                result.text = "✅ SAFE ${result.urlType.uppercase()}"
                result.setTextColor(getColor(android.R.color.holo_green_dark))
            }
            "INVALID" -> {
                result.text = "❌ INVALID INPUT"
                result.setTextColor(getColor(android.R.color.darker_gray))
            }
            else -> {
                result.text = "❓ UNKNOWN"
                result.setTextColor(getColor(android.R.color.darker_gray))
            }
        }

        val cacheInfo = if (result.fromCache) " (from cache)" else ""
        val confidencePercent = (result.confidence * 100).toInt()
        staus.text = "Confidence: $confidencePercent%$cacheInfo"

        val lines = mutableListOf<String>()
        result.domn?.let { lines.add(it) }
        result.blacklist?.let { lines.add(it) }
        intel.text = lines.joinToString("\n")
    }

    data class ApiResponse(
        val verdict: String,
        val urlType: String,
        val confidence: Double,
        val fromCache: Boolean,
        val message: String,
        val domn: String?,
        val blacklist: String?
    )
}
