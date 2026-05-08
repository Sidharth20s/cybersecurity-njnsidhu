# Keep our service classes — they're called via reflection by the system
-keep class com.silentsentinel.** { *; }

# Don't obfuscate receiver classes (manifest references them by name)
-keep class com.silentsentinel.BootReceiver { *; }
-keep class com.silentsentinel.SmsTriggerReceiver { *; }

# Strip all logging in release builds
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}
