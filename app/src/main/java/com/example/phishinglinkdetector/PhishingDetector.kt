package com.example.phishinglinkdetector

import android.content.Context
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Simple on-device ML detector using TensorFlow Lite
 */
class PhishingDetector(private val context: Context) {
    
    private var interpreter: Interpreter? = null
    private val modelPath = "phishing_model.tflite"
    
    /**
     * Initialize the TensorFlow Lite model
     */
    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            val modelBuffer = loadModelFile()
            interpreter = Interpreter(modelBuffer)
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
    
    /**
     * Load model from assets
     */
    private fun loadModelFile(): MappedByteBuffer {
        val fileDescriptor = context.assets.openFd(modelPath)
        val inputStream = FileInputStream(fileDescriptor.createInputStream())
        val fileChannel = inputStream.channel
        val startOffset = fileDescriptor.startOffset
        val declaredLength = fileDescriptor.declaredLength
        return fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
    }
    
    /**
     * Predict if URL is phishing
     * Returns: Pair(isPhishing: Boolean, confidence: Float)
     */
    fun predict(url: String): Pair<Boolean, Float> {
        val interpreter = this.interpreter ?: throw IllegalStateException("Model not initialized")
        
        // Extract features
        val features = FeatureExtractor.extractFeatures(url)
        
        // Prepare input/output buffers
        val inputBuffer = Array(1) { features }
        val outputBuffer = Array(1) { FloatArray(1) }
        
        // Run inference
        interpreter.run(inputBuffer, outputBuffer)
        
        // Get prediction (output is probability of phishing)
        val phishingProbability = outputBuffer[0][0]
        val isPhishing = phishingProbability > 0.5f
        val confidence = if (isPhishing) phishingProbability else (1f - phishingProbability)
        
        return Pair(isPhishing, confidence)
    }
    
    /**
     * Check if model is loaded
     */
    fun isInitialized(): Boolean = interpreter != null
    
    /**
     * Clean up resources
     */
    fun close() {
        interpreter?.close()
        interpreter = null
    }
}
