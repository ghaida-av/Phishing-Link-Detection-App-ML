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

        bindViews()

        detector = PhishingDetector(this)
        loadModelAsync()

        checkBtn.setOnClickListener { onCheckClicked() }
    }

    private fun bindViews() {
        linkInput = findViewById(R.id.linkInput)
        checkBtn = findViewById(R.id.checkBtn)
        resultText = findViewById(R.id.resultText)
        statusText = findViewById(R.id.statusText)
        intelText = findViewById(R.id.intelText)
    }

    private fun loadModelAsync() {
        lifecycleScope.launch {
            statusText.text = "Loading ML model..."
            val ok = detector.initialize()

            if (ok) {
                statusText.text = "Ready - Enter URL to check"
            } else {
                statusText.text = "Error loading model"
                checkBtn.isEnabled = false
            }
        }
    }

    private fun onCheckClicked() {
        val inputText = linkInput.text.toString().trim()

        if (inputText.isEmpty()) {
            showMessage("Please enter a URL or email")
            return
        }

        if (!detector.isInitialized()) {
            resultText.text = "Model not ready yet"
            statusText.text = "Please wait..."
            return
        }

        checkUrlAsync(inputText)
    }

    private fun showMessage(message: String) {
        resultText.text = message
        statusText.text = ""
        intelText.text = ""
    }

    private fun setBusy(isBusy: Boolean) {
        checkBtn.isEnabled = !isBusy
        if (isBusy) {
            resultText.text = "Checking..."
            statusText.text = ""
            intelText.text = ""
        }
    }

    private fun checkUrlAsync(url: String) {
        setBusy(true)

        lifecycleScope.launch {
            try {
                val (isPhishing, confidence) = detector.predict(url)
                showResult(isPhishing, confidence, url)
            } catch (e: Exception) {
                resultText.text = "❌ Error: ${e.message}"
                statusText.text = "Check your input format"
                intelText.text = ""
            } finally {
                setBusy(false)
            }
        }
    }

    private fun showResult(isPhishing: Boolean, confidence: Float, url: String) {
        val resultColor = if (isPhishing) {
            resultText.text = "⚠ PHISHING DETECTED"
            android.R.color.holo_red_dark
        } else {
            resultText.text = "✅ SAFE URL"
            android.R.color.holo_green_dark
        }
        resultText.setTextColor(getColor(resultColor))

        val confidencePercent = (confidence * 100).toInt()
        statusText.text = "Confidence: $confidencePercent%"
        statusText.setTextColor(getColor(android.R.color.darker_gray))

        val urlType = if (url.contains("@")) "Email" else "URL"
        val shortUrl = if (url.length > 50) url.take(50) + "..." else url
        intelText.text = "Type: $urlType\nAnalyzed: $shortUrl\nOn-device ML detection"
    }

    override fun onDestroy() {
        super.onDestroy()
        detector.close()
    }
}
