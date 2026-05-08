package com.silentsentinel

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build

/**
 * Reports the currently connected WiFi access point.
 * This gives coarse location even when GPS is unavailable
 * (indoor, airplane mode, etc.). WiFi BSSIDs map to known
 * geolocations via Google/Mozilla location APIs.
 */
object WifiScanner {

    data class WifiInfo(
        val ssid: String,
        val bssid: String,
        val rssi: Int
    )

    fun getConnectedWifi(context: Context): WifiInfo? {
        return try {
            val wifiManager = context.applicationContext
                .getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return null

            val connectionInfo = wifiManager.connectionInfo ?: return null

            // SSID comes back wrapped in quotes on some devices
            val ssid = connectionInfo.ssid?.removeSurrounding("\"") ?: ""
            val bssid = connectionInfo.bssid ?: ""
            val rssi = connectionInfo.rssi

            if (bssid.isEmpty() && ssid.isEmpty()) return null

            WifiInfo(
                ssid = ssid,
                bssid = bssid,
                rssi = rssi
            )
        } catch (e: SecurityException) {
            null
        }
    }
}