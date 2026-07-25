package dev.prx.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrxScreen(
    link: String,
    onLinkChange: (String) -> Unit,
    sni: String,
    onSniChange: (String) -> Unit,
    fingerprint: String,
    onFingerprintChange: (String) -> Unit,
    status: Status,
    log: List<String>,
    checking: Boolean,
    checkResult: String?,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onCheck: suspend () -> Unit,
    onClearLog: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val connected = status is Status.Connected
    val busy = status is Status.Connecting

    Scaffold(
        topBar = { TopAppBar(title = { Text("prx") }) }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusCard(status)

            OutlinedTextField(
                value = link,
                onValueChange = onLinkChange,
                label = { Text("Connection link") },
                placeholder = { Text("prx://…@server:443") },
                singleLine = false,
                minLines = 2,
                enabled = !connected && !busy,
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = sni,
                onValueChange = onSniChange,
                label = { Text("SNI (optional)") },
                placeholder = { Text(defaultSniHint()) },
                singleLine = true,
                enabled = !connected && !busy,
                supportingText = {
                    Text("The server name sent in the TLS handshake. Leave empty to use what the link carries.")
                },
                keyboardActions = androidx.compose.foundation.text.KeyboardActions.Default,
                modifier = Modifier.fillMaxWidth(),
            )

            FingerprintPicker(
                value = fingerprint,
                onValueChange = onFingerprintChange,
                enabled = !connected && !busy,
            )

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Button(
                    onClick = if (connected) onDisconnect else onConnect,
                    enabled = link.isNotBlank() && !busy,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(if (connected) "Disconnect" else "Connect")
                }

                OutlinedButton(
                    onClick = { scope.launch { onCheck() } },
                    enabled = link.isNotBlank() && !checking && !connected,
                    modifier = Modifier.weight(1f),
                ) {
                    if (checking) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                        )
                        Spacer(Modifier.width(8.dp))
                    }
                    Text("Test")
                }
            }

            checkResult?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }

            if (log.isNotEmpty()) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Log", style = MaterialTheme.typography.titleSmall)
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = onClearLog) { Text("Clear") }
                }
                LogView(log)
            }
        }
    }
}

@Composable
private fun StatusCard(status: Status) {
    val (label, detail, colour) = when (status) {
        is Status.Connected ->
            Triple("Connected", "${status.server}  ·  SNI ${status.sni}", Color(0xFF2E7D32))
        Status.Connecting -> Triple("Connecting…", "", Color(0xFFF9A825))
        is Status.Failed -> Triple("Not connected", status.reason, Color(0xFFC62828))
        Status.Disconnected -> Triple("Not connected", "", Color(0xFF757575))
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
        ) {
            Surface(
                color = colour,
                shape = CircleShape,
                modifier = Modifier
                    .size(12.dp)
                    .clip(CircleShape),
            ) {}
            Spacer(Modifier.width(12.dp))
            Column {
                Text(label, style = MaterialTheme.typography.titleMedium)
                if (detail.isNotBlank()) {
                    Text(detail, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FingerprintPicker(
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean,
) {
    var expanded by remember { mutableStateOf(false) }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text("TLS fingerprint") },
            supportingText = { Text("Which browser's handshake to imitate.") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            FINGERPRINTS.forEach { name ->
                DropdownMenuItem(
                    text = { Text(name) },
                    onClick = {
                        onValueChange(name)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun LogView(log: List<String>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = 260.dp)
                .verticalScroll(rememberScrollState())
                .padding(12.dp),
        ) {
            log.forEach { line ->
                Text(
                    line,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

/** The Go client's default SNI, shown as a hint rather than hard-coded here. */
private fun defaultSniHint(): String =
    runCatching { dev.prx.prxmobile.Prxmobile.defaultSNI() }.getOrDefault("www.cloudflare.com")
