package com.example.phishinglinkdetector

import android.content.Context
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Runs the TensorFlow Lite phishing model on-device (offline).
 *
 * - Loads `phishing_model.tflite` from `app/src/main/assets/`
 * - Extracts features using `FeatureExtractor`
 * - Runs inference with `Interpreter`
 */
class PhishingDetector(private val context: Context) {

    private var interpreter: Interpreter? = null
    private val modelFileName = "phishing_model.tflite"

    /** Load the model from assets and create the TFLite interpreter. */
    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            interpreter = Interpreter(loadModelFromAssets())
            return@withContext true
        } catch (e: Exception) {
            e.printStackTrace()
            return@withContext false
        }
    }

    /** Read the `.tflite` file as a memory-mapped buffer (fast + low memory). */
    private fun loadModelFromAssets(): MappedByteBuffer {
        val assetFd = context.assets.openFd(modelFileName)
        FileInputStream(assetFd.fileDescriptor).use { inputStream ->
            val channel = inputStream.channel
            return channel.map(FileChannel.MapMode.READ_ONLY, assetFd.startOffset, assetFd.declaredLength)
        }
    }

    /**
     * Predict if input URL is phishing.
     *
     * Output of the model is a probability \(0..1\) of phishing.
     * We turn that into:
     * - isPhishing: probability > 0.5
     * - confidence: probability if phishing, otherwise (1 - probability)
     */
    fun predict(url: String): Pair<Boolean, Float> {
        val tflite = interpreter ?: throw IllegalStateException("Model not initialized")

        val features: FloatArray = FeatureExtractor.extractFeatures(url)

        val input: Array<FloatArray> = arrayOf(features)          // shape: [1, featureCount]
        val output: Array<FloatArray> = arrayOf(floatArrayOf(0f)) // shape: [1, 1]

        tflite.run(input, output)

        val phishingProbability = output[0][0]
        val isPhishing = phishingProbability > 0.5f
        val confidence = if (isPhishing) phishingProbability else (1f - phishingProbability)

        return isPhishing to confidence
    }

    /** True when the model has been loaded successfully. */
    fun isInitialized(): Boolean {
        return interpreter != null
    }

    /** Free native resources held by the TFLite interpreter. */
    fun close() {
        interpreter?.close()
        interpreter = null
    }
}
