package dev.prx.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/** What the tunnel is doing right now. */
sealed interface Status {
    data object Disconnected : Status
    data object Connecting : Status
    data class Connected(val server: String, val sni: String) : Status
    data class Failed(val reason: String) : Status
}

/**
 * The single place the service and the UI agree on.
 *
 * The service runs independently of any activity -- the user can swipe the
 * app away while the tunnel stays up -- so state lives here rather than in a
 * ViewModel that dies with the screen.
 */
object TunnelState {

    private val _status = MutableStateFlow<Status>(Status.Disconnected)
    val status: StateFlow<Status> = _status

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log

    private const val MAX_LOG_LINES = 200

    fun connecting() {
        _status.value = Status.Connecting
    }

    fun connected(server: String, sni: String) {
        _status.value = Status.Connected(server, sni)
    }

    fun disconnected() {
        _status.value = Status.Disconnected
    }

    fun fail(reason: String) {
        appendLog("error: $reason")
        _status.value = Status.Failed(reason)
    }

    fun appendLog(line: String) {
        _log.update { lines ->
            (lines + line).takeLast(MAX_LOG_LINES)
        }
    }

    fun clearLog() {
        _log.value = emptyList()
    }
}
