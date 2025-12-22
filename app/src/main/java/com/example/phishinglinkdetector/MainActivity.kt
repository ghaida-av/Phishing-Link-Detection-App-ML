package com.example.phishinglinkdetector


import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val linkInput = findViewById<EditText>(R.id.linkInput)
        val checkBtn = findViewById<Button>(R.id.checkBtn)
        val resultText = findViewById<TextView>(R.id.resultText)

        checkBtn.setOnClickListener {
            val url = linkInput.text.toString()

            if (isPhishing(url)) {
                resultText.text = "⚠ PHISHING LINK"
            } else {
                resultText.text = "✅ SAFE LINK"
            }
        }
    }

    private fun isPhishing(url: String): Boolean {
        val lowerUrl = url.lowercase()

        return lowerUrl.contains("@") ||
                lowerUrl.contains("login") ||
                lowerUrl.contains("verify") ||
                lowerUrl.contains("bank") ||
                lowerUrl.length > 75
    }
}
