package dev.prx.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.prx.prxmobile.Logger
import dev.prx.prxmobile.Protector
import dev.prx.prxmobile.Prxmobile
import dev.prx.prxmobile.Tunnel
import kotlin.concurrent.thread

/**
 * Carries the whole device's traffic through a prx server.
 *
 * Android hands a VPN app a tun descriptor and expects IP packets to be read
 * from and written to it. The Go side turns that descriptor into a userspace
 * network stack, so what arrives here as packets leaves as ordinary
 * connections through the tunnel.
 */
class PrxVpnService : VpnService() {

    private var tunnel: Tunnel? = null
    private var descriptor: ParcelFileDescriptor? = null

    /**
     * Exempts our own connection to the server from the tunnel we provide.
     *
     * Without this the client's socket would be routed into the tun device it
     * is serving, and the connection could never leave the phone.
     */
    private val protector = Protector { fd -> protect(fd.toInt()) }

    private val logger = Logger { line ->
        Log.i(TAG, line)
        TunnelState.appendLog(line)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }

        val profile = Profile(
            link = intent?.getStringExtra(EXTRA_LINK).orEmpty(),
            sni = intent?.getStringExtra(EXTRA_SNI).orEmpty(),
            fingerprint = intent?.getStringExtra(EXTRA_FINGERPRINT).orEmpty(),
        )
        if (profile.link.isBlank()) {
            TunnelState.fail("No connection link was provided")
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))
        TunnelState.connecting()

        // Establishing the tunnel touches the network stack; keep it off the
        // main thread so a slow start never freezes the UI.
        thread(name = "prx-start") { connect(profile) }
        return START_STICKY
    }

    private fun connect(profile: Profile) {
        try {
            val builder = Builder()
                .setSession(SESSION_NAME)
                .setMtu(MTU)
                // A private address inside the tunnel; nothing routes to it,
                // it only gives the stack an interface to answer from.
                .addAddress("10.7.0.2", 32)
                .addRoute("0.0.0.0", 0)
                // IPv6 is captured as well. Leaving it out would let IPv6
                // traffic bypass the tunnel entirely, which is exactly the
                // leak a VPN is supposed to prevent. If the server has no
                // IPv6 the attempts fail fast and applications fall back.
                .addAddress("fd00:7:0:0:0:0:0:2", 128)
                .addRoute("::", 0)
                // Names are resolved at the far end: these queries become UDP
                // packets inside the tunnel like any other traffic.
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addDnsServer("2606:4700:4700::1111")

            // Belt and braces alongside protect(): our own traffic never
            // enters the tunnel.
            runCatching { builder.addDisallowedApplication(packageName) }

            val pfd = builder.establish()
                ?: throw IllegalStateException("VPN permission was revoked")
            descriptor = pfd

            // The Go side takes ownership of the descriptor and closes it.
            val fd = pfd.detachFd()
            descriptor = null

            val started = Prxmobile.start(
                profile.link,
                profile.sni,
                profile.fingerprint,
                fd.toLong(),
                MTU.toLong(),
                protector,
                logger,
            )
            tunnel = started

            TunnelState.connected(started.server(), started.sni())
            updateNotification("Connected · ${started.server()}")
        } catch (t: Throwable) {
            Log.e(TAG, "could not start the tunnel", t)
            TunnelState.fail(t.message ?: t.toString())
            shutdown()
        }
    }

    /** Called when the user or another VPN app takes the tunnel away. */
    override fun onRevoke() {
        Log.i(TAG, "tunnel revoked by the system")
        shutdown()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun shutdown() {
        tunnel?.let { runCatching { it.stop() } }
        tunnel = null
        descriptor?.let { runCatching { it.close() } }
        descriptor = null

        TunnelState.disconnected()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ------------------------------------------------------------ notification

    private fun buildNotification(text: String): Notification {
        ensureChannel()

        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getService(
            this,
            1,
            Intent(this, PrxVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(null, "Disconnect", disconnect).build()
            )
            .build()
    }

    private fun updateNotification(text: String) {
        notificationManager().notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Tunnel status",
            NotificationManager.IMPORTANCE_LOW,
        ).apply { setShowBadge(false) }
        notificationManager().createNotificationChannel(channel)
    }

    private fun notificationManager() =
        getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private data class Profile(
        val link: String,
        val sni: String,
        val fingerprint: String,
    )

    companion object {
        private const val TAG = "prx"
        private const val SESSION_NAME = "prx"
        private const val MTU = 1500
        private const val CHANNEL_ID = "prx.tunnel"
        private const val NOTIFICATION_ID = 1

        const val ACTION_STOP = "dev.prx.app.STOP"
        const val EXTRA_LINK = "link"
        const val EXTRA_SNI = "sni"
        const val EXTRA_FINGERPRINT = "fingerprint"

        fun start(context: Context, link: String, sni: String, fingerprint: String) {
            val intent = Intent(context, PrxVpnService::class.java)
                .putExtra(EXTRA_LINK, link)
                .putExtra(EXTRA_SNI, sni)
                .putExtra(EXTRA_FINGERPRINT, fingerprint)
            context.startService(intent)
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, PrxVpnService::class.java).setAction(ACTION_STOP)
            )
        }
    }
}
