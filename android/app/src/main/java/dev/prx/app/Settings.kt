package dev.prx.app

import android.content.Context

/**
 * The connection the user last entered.
 *
 * The link contains the pre-shared key, so it lives in the app's private
 * preferences file, which is readable only by this app.
 */
class Settings(context: Context) {

    private val prefs =
        context.getSharedPreferences("prx", Context.MODE_PRIVATE)

    var link: String
        get() = prefs.getString(KEY_LINK, "").orEmpty()
        set(value) = prefs.edit().putString(KEY_LINK, value).apply()

    var sni: String
        get() = prefs.getString(KEY_SNI, "").orEmpty()
        set(value) = prefs.edit().putString(KEY_SNI, value).apply()

    var fingerprint: String
        get() = prefs.getString(KEY_FINGERPRINT, "").orEmpty()
        set(value) = prefs.edit().putString(KEY_FINGERPRINT, value).apply()

    private companion object {
        const val KEY_LINK = "link"
        const val KEY_SNI = "sni"
        const val KEY_FINGERPRINT = "fingerprint"
    }
}

/** ClientHello templates the Go client understands. */
val FINGERPRINTS = listOf(
    "chrome", "firefox", "safari", "ios", "edge", "android", "random",
)
