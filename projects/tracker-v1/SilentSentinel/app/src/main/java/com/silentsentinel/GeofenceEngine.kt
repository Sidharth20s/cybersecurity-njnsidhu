package com.silentsentinel

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/**
 * Evaluates whether the device has entered or exited a defined
 * geofence zone. Alerts are only sent on state transitions,
 * not on every location update.
 *
 * Zones are pushed from the C2 server and stored locally.
 */
class GeofenceEngine(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(
        "geofence_prefs", Context.MODE_PRIVATE
    )

    data class GeofenceZone(
        val name: String,
        val lat: Double,
        val lng: Double,
        val radiusMeters: Float,
        val triggerOnEntry: Boolean,
        val triggerOnExit: Boolean
    )

    data class GeofenceEvent(
        val zoneName: String,
        val type: String,  // "entry" or "exit"
        val lat: Double,
        val lng: Double
    )

    /**
     * Load zones from server payload (JSON array).
     * Call this when you receive updated config from C2.
     */
    fun loadZonesFromJson(json: String) {
        prefs.edit().putString("zones", json).apply()
    }

    /**
     * Get currently stored zones.
     */
    fun getZones(): List<GeofenceZone> {
        val raw = prefs.getString("zones", "[]") ?: "[]"
        val arr = JSONArray(raw)
        val zones = mutableListOf<GeofenceZone>()
        for (i in 0 until arr.length()) {
            val obj = arr.getJSONObject(i)
            zones.add(
                GeofenceZone(
                    name = obj.getString("name"),
                    lat = obj.getDouble("lat"),
                    lng = obj.getDouble("lng"),
                    radiusMeters = obj.getDouble("radius_meters").toFloat(),
                    triggerOnEntry = obj.optBoolean("trigger_on_entry", true),
                    triggerOnExit = obj.optBoolean("trigger_on_exit", true)
                )
            )
        }
        return zones
    }

    /**
     * Check current location against all zones.
     * Returns list of events (entry/exit) that just transitioned.
     */
    fun checkZones(lat: Double, lng: Double): List<GeofenceEvent> {
        val zones = getZones()
        val previousStates = getPreviousStates()
        val currentStates = mutableMapOf<String, Boolean>()
        val events = mutableListOf<GeofenceEvent>()

        for (zone in zones) {
            val distance = haversineDistance(lat, lng, zone.lat, zone.lng)
            val inside = distance <= zone.radiusMeters

            currentStates[zone.name] = inside
            val wasInside = previousStates[zone.name] ?: false

            if (inside && !wasInside && zone.triggerOnEntry) {
                events.add(GeofenceEvent(zone.name, "entry", lat, lng))
            }
            if (!inside && wasInside && zone.triggerOnExit) {
                events.add(GeofenceEvent(zone.name, "exit", lat, lng))
            }
        }

        // Persist current state
        saveCurrentStates(currentStates)
        return events
    }

    private fun getPreviousStates(): Map<String, Boolean> {
        val raw = prefs.getString("state", "{}") ?: "{}"
        val obj = JSONObject(raw)
        val map = mutableMapOf<String, Boolean>()
        for (key in obj.keys()) {
            map[key] = obj.getBoolean(key)
        }
        return map
    }

    private fun saveCurrentStates(states: Map<String, Boolean>) {
        val obj = JSONObject()
        for ((k, v) in states) obj.put(k, v)
        prefs.edit().putString("state", obj.toString()).apply()
    }

    /**
     * Haversine distance in meters between two lat/lng points.
     */
    private fun haversineDistance(lat1: Double, lng1: Double, lat2: Double, lng2: Double): Float {
        val R = 6371000.0 // Earth radius in meters
        val dLat = Math.toRadians(lat2 - lat1)
        val dLng = Math.toRadians(lng2 - lng1)
        val a = Math.sin(dLat / 2).pow(2) +
                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
                Math.sin(dLng / 2).pow(2)
        val c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
        return (R * c).toFloat()
    }
}