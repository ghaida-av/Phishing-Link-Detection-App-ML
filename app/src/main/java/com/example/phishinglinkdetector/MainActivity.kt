package com.example.phishinglinkdetector

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var linkInput: EditText
    private lateinit var checkBtn: Button
    private lateinit var resultText: TextView
    private lateinit var statusText: TextView
    private lateinit var intelText: TextView
    
    private lateinit var detector: PhishingDetector

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        linkInput = findViewById(R.id.linkInput)
        checkBtn = findViewById(R.id.checkBtn)
        resultText = findViewById(R.id.resultText)
        statusText = findViewById(R.id.statusText)
        intelText = findViewById(R.id.intelText)

        // Initialize ML detector
        detector = PhishingDetector(this)
        
        // Load model in background
        lifecycleScope.launch {
            statusText.text = "Loading ML model..."
            val initialized = detector.initialize()
            if (initialized) {
                statusText.text = "Ready - Enter URL to check"
            } else {
                statusText.text = "Error loading model"
                checkBtn.isEnabled = false
            }
        }

        checkBtn.setOnClickListener {
            val input = linkInput.text.toString().trim()
            
            if (input.isEmpty()) {
                resultText.text = "Please enter a URL or email"
                statusText.text = ""
                intelText.text = ""
                return@setOnClickListener
            }

            if (!detector.isInitialized()) {
                resultText.text = "Model not ready yet"
                statusText.text = "Please wait..."
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
                // Use on-device ML model
                val (isPhishing, confidence) = detector.predict(url)
                
                // Display result
                displayResult(isPhishing, confidence, url)
                
            } catch (e: Exception) {
                resultText.text = "❌ Error: ${e.message}"
                statusText.text = "Check your input format"
                intelText.text = ""
            } finally {
                checkBtn.isEnabled = true
            }
        }
    }

    private fun displayResult(isPhishing: Boolean, confidence: Float, url: String) {
        if (isPhishing) {
            resultText.text = "⚠ PHISHING DETECTED"
            resultText.setTextColor(getColor(android.R.color.holo_red_dark))
        } else {
            resultText.text = "✅ SAFE URL"
            resultText.setTextColor(getColor(android.R.color.holo_green_dark))
        }

        val confidencePercent = (confidence * 100).toInt()
        statusText.text = "Confidence: $confidencePercent%"
        statusText.setTextColor(getColor(android.R.color.darker_gray))

        // Show URL type and basic info
        val urlType = if (url.contains("@")) "Email" else "URL"
        val info = buildString {
            append("Type: $urlType\n")
            append("Analyzed: ${url.take(50)}${if (url.length > 50) "..." else ""}\n")
            append("On-device ML detection")
        }
        intelText.text = info
    }

    override fun onDestroy() {
        super.onDestroy()
        detector.close()
    }
}
