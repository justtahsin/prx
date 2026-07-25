package dev.prx.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.prx.prxmobile.Prxmobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    /** The link a tapped prx:// URL arrived with, if any. */
    private var incomingLink by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        incomingLink = linkFrom(intent)
        requestNotificationPermission()

        setContent {
            PrxTheme {
                PrxApp(
                    incomingLink = incomingLink,
                    onIncomingLinkConsumed = { incomingLink = null },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        linkFrom(intent)?.let { incomingLink = it }
    }

    private fun linkFrom(intent: Intent?): String? =
        intent?.data?.takeIf { it.scheme == "prx" }?.toString()

    /**
     * Android 13+ needs consent before the tunnel's ongoing notification can
     * be shown. Refusing it does not stop the tunnel, so the result is not
     * acted on.
     */
    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this, Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
    }
}

@Composable
fun PrxApp(
    incomingLink: String?,
    onIncomingLinkConsumed: () -> Unit,
) {
    val context = LocalContext.current
    val settings = remember { Settings(context) }

    var link by remember { mutableStateOf(settings.link) }
    var sni by remember { mutableStateOf(settings.sni) }
    var fingerprint by remember { mutableStateOf(settings.fingerprint.ifBlank { "chrome" }) }

    var checking by remember { mutableStateOf(false) }
    var checkResult by remember { mutableStateOf<String?>(null) }

    val status by TunnelState.status.collectAsStateWithLifecycle()
    val log by TunnelState.log.collectAsStateWithLifecycle()

    // A link opened from outside replaces what is in the field.
    LaunchedEffect(incomingLink) {
        incomingLink?.let {
            link = it
            settings.link = it
            onIncomingLinkConsumed()
        }
    }

    // Android shows its own consent dialog the first time a VPN is
    // configured; the tunnel may only start once that is granted.
    val vpnConsent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            PrxVpnService.start(context, link.trim(), sni.trim(), fingerprint)
        } else {
            TunnelState.fail("VPN permission was declined")
        }
    }

    fun connect() {
        settings.link = link.trim()
        settings.sni = sni.trim()
        settings.fingerprint = fingerprint
        checkResult = null

        val consent = VpnService.prepare(context)
        if (consent != null) {
            vpnConsent.launch(consent)
        } else {
            PrxVpnService.start(context, link.trim(), sni.trim(), fingerprint)
        }
    }

    fun disconnect() = PrxVpnService.stop(context)

    suspend fun runCheck() {
        checking = true
        checkResult = try {
            val exitIp = withContext(Dispatchers.IO) {
                // No protector: the check runs before the tunnel is up, so
                // the socket is not being captured yet.
                Prxmobile.check(link.trim(), sni.trim(), fingerprint, 20L, null) { line ->
                    TunnelState.appendLog(line)
                }
            }
            "Works — traffic exits from $exitIp"
        } catch (t: Throwable) {
            "Failed — ${t.message ?: t.toString()}"
        }
        checking = false
    }

    PrxScreen(
        link = link,
        onLinkChange = { link = it },
        sni = sni,
        onSniChange = { sni = it },
        fingerprint = fingerprint,
        onFingerprintChange = { fingerprint = it },
        status = status,
        log = log,
        checking = checking,
        checkResult = checkResult,
        onConnect = ::connect,
        onDisconnect = ::disconnect,
        onCheck = { runCheck() },
        onClearLog = TunnelState::clearLog,
    )
}
