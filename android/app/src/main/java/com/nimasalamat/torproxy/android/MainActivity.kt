package com.nimasalamat.torproxy.android

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Proxy
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import org.json.JSONObject
import org.torproject.jni.TorService
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy as JavaProxy
import java.net.URL
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val io = Executors.newFixedThreadPool(3)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("torproxy-mobile", Context.MODE_PRIVATE) }

    private lateinit var statusView: TextView
    private lateinit var detailView: TextView
    private lateinit var endpointsView: TextView
    private lateinit var transportSpinner: Spinner
    private lateinit var transportHint: TextView
    private lateinit var bridgeInput: EditText
    private lateinit var connectButton: Button
    private lateinit var identityButton: Button
    private lateinit var testButton: Button

    @Volatile
    private var torService: TorService? = null
    private var isBound = false
    private var isStarting = false
    private var isConnected = false
    private var receiverRegistered = false
    private var generation = 0
    private var activeTransport = TransportType.DIRECT

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as? TorService.LocalBinder
            torService = localBinder?.service
            if (torService == null) {
                isStarting = false
                showFailure("Tor service did not return its local binder.")
                refreshButtons()
                return
            }
            isStarting = false
            connectButton.text = "Stop Tor"
            setStatus(
                "Starting Tor",
                "Waiting for the first Tor circuit. No direct-network fallback is used."
            )
            mainHandler.removeCallbacks(bootstrapPoll)
            mainHandler.post(bootstrapPoll)
            refreshButtons()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            torService = null
            isBound = false
            isConnected = false
            isStarting = false
            setStatus("Tor service stopped", "The local proxy is unavailable.")
            refreshButtons()
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent == null) return
            when (intent.action) {
                TorService.ACTION_STATUS -> {
                    when (intent.getStringExtra(TorService.EXTRA_STATUS)) {
                        TorService.STATUS_STARTING -> {
                            isConnected = false
                            setStatus("Starting Tor", "Preparing the local Tor proxy.")
                        }
                        TorService.STATUS_ON -> {
                            isConnected = true
                            setStatus(
                                "Connected to Tor",
                                "Tor reports that a circuit is established."
                            )
                            refreshEndpoints()
                        }
                        TorService.STATUS_STOPPING, TorService.STATUS_OFF -> {
                            isConnected = false
                            if (!isStarting) {
                                setStatus("Disconnected", "Tor is not connected.")
                            }
                        }
                    }
                    refreshButtons()
                }
                TorService.ACTION_ERROR -> {
                    val message = intent.getStringExtra(Intent.EXTRA_TEXT)
                    showFailure(message ?: "Tor reported a startup error.")
                }
            }
        }
    }

    private val bootstrapPoll = object : Runnable {
        override fun run() {
            val service = torService ?: return
            io.execute {
                val phase = try {
                    service.getInfo("status/bootstrap-phase").orEmpty()
                } catch (_: Exception) {
                    ""
                }
                val progress = Regex("PROGRESS=(\\d+)")
                    .find(phase)?.groupValues?.getOrNull(1)?.toIntOrNull()
                val socksPort = try {
                    service.socksPort
                } catch (_: Exception) {
                    -1
                }
                val httpPort = try {
                    service.httpTunnelPort
                } catch (_: Exception) {
                    -1
                }

                runOnUiThread {
                    if (isFinishing || isDestroyed || torService !== service) return@runOnUiThread
                    if (!isConnected && progress != null) {
                        val summary = if (progress >= 100) {
                            "Tor bootstrap complete; waiting for a confirmed circuit."
                        } else {
                            "Connecting to Tor · " + progress + "%"
                        }
                        setStatus(
                            summary,
                            "Progress is read from Tor itself, not from a generic connectivity check."
                        )
                    }
                    endpointsView.text = endpointText(socksPort, httpPort)
                    refreshButtons()
                }
            }
            mainHandler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.rgb(11, 16, 20)
        window.navigationBarColor = Color.rgb(11, 16, 20)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            window.decorView.systemUiVisibility = 0
        }
        setContentView(buildUi())
        registerStatusReceiver()
        setStatus(
            "Disconnected",
            "The Tor daemon is embedded in the app through the Tor Android library."
        )
        refreshEndpoints()
    }

    private fun buildUi(): View {
        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.rgb(11, 16, 20))
            isFillViewport = true
        }
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(28))
        }
        scroll.addView(page, ScrollView.LayoutParams(-1, -2))

        addText(page, "TORPROXY", 13f, Color.rgb(80, 218, 190), true, 4)
        addText(page, "Mobile", 32f, Color.WHITE, true, 3)
        addText(page, "Embedded Tor · Android", 15f, Color.rgb(163, 178, 188), false, 22)

        val statusCard = card(page)
        statusView = addText(statusCard, "Disconnected", 20f, Color.WHITE, true, 6)
        detailView = addText(
            statusCard,
            "Waiting for status.",
            13f,
            Color.rgb(163, 178, 188),
            false,
            14
        )
        endpointsView = addText(
            statusCard,
            endpointText(-1, -1),
            13f,
            Color.rgb(126, 211, 191),
            true,
            0
        )

        connectButton = makeButton("Start Tor", Color.rgb(29, 173, 145))
        connectButton.setOnClickListener {
            if (isBound || isStarting) stopTor() else startTor()
        }
        page.addView(connectButton, marginParams(bottom = 10, top = 12))

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        identityButton = makeButton("New identity", Color.rgb(37, 52, 64))
        identityButton.setOnClickListener { requestNewIdentity() }
        testButton = makeButton("Test Tor IP", Color.rgb(37, 52, 64))
        testButton.setOnClickListener { testTorExit() }
        actions.addView(
            identityButton,
            LinearLayout.LayoutParams(0, dp(48), 1f).apply { marginEnd = dp(6) }
        )
        actions.addView(
            testButton,
            LinearLayout.LayoutParams(0, dp(48), 1f).apply { marginStart = dp(6) }
        )
        page.addView(actions, marginParams(bottom = 20))

        val transportCard = card(page)
        addText(transportCard, "Connection method", 17f, Color.WHITE, true, 6)
        addText(
            transportCard,
            "Choose direct Tor or a pluggable transport matching your bridge records.",
            13f,
            Color.rgb(163, 178, 188),
            false,
            10
        )
        transportSpinner = Spinner(this)
        val spinnerAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            TransportType.values().map { it.label }
        )
        spinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        transportSpinner.adapter = spinnerAdapter
        transportSpinner.setSelection(
            prefs.getInt("transport", 0).coerceIn(0, TransportType.values().lastIndex)
        )
        transportCard.addView(transportSpinner, marginParams(bottom = 6))
        transportHint = addText(
            transportCard,
            "",
            12f,
            Color.rgb(126, 211, 191),
            false,
            0
        )
        updateTransportHint()
        transportSpinner.onItemSelectedListener =
            object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(
                    parent: AdapterView<*>?,
                    view: View?,
                    position: Int,
                    id: Long
                ) {
                    updateTransportHint()
                }

                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }

        val bridgesCard = card(page)
        addText(bridgesCard, "Bridges", 17f, Color.WHITE, true, 6)
        addText(
            bridgesCard,
            "Paste one bridge per line. An obfs4 bridge starts with obfs4; a WebTunnel bridge starts with webtunnel. Bridge records are stored on this device.",
            13f,
            Color.rgb(163, 178, 188),
            false,
            10
        )
        bridgeInput = EditText(this).apply {
            setText(prefs.getString("bridges", ""))
            hint = "obfs4 host:port fingerprint cert=… iat-mode=0"
            hintTextColor = Color.rgb(104, 120, 131)
            setTextColor(Color.WHITE)
            textSize = 13f
            gravity = Gravity.TOP or Gravity.START
            minLines = 3
            maxLines = 7
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setPadding(dp(12), dp(12), dp(12), dp(12))
            background = roundedBackground(
                Color.rgb(8, 13, 17),
                Color.rgb(49, 68, 79),
                10
            )
        }
        bridgesCard.addView(bridgeInput, marginParams(bottom = 8))
        addText(
            bridgesCard,
            "Use bridge records obtained from a source you trust. The selected transport must match each bridge line.",
            12f,
            Color.rgb(230, 183, 104),
            false,
            0
        )

        val limitations = card(page)
        addText(limitations, "Proxy endpoints", 17f, Color.WHITE, true, 6)
        addText(
            limitations,
            "This build exposes local proxy endpoints for compatible apps. It does not yet install an Android VPN or automatically route all phone traffic.",
            13f,
            Color.rgb(163, 178, 188),
            false,
            0
        )
        addText(
            page,
            "Tor is not a guarantee of anonymity. Only connections routed through these proxy endpoints use Tor.",
            12f,
            Color.rgb(122, 138, 148),
            false,
            8
        )

        return scroll
    }

    private fun startTor() {
        if (isBound || isStarting) return

        val type = TransportType.values().getOrElse(transportSpinner.selectedItemPosition) {
            TransportType.DIRECT
        }
        val bridges = try {
            TorConfigBuilder.normalizeBridgeLines(bridgeInput.text.toString(), type)
        } catch (error: IllegalArgumentException) {
            showFailure(error.message ?: "Invalid bridge configuration.")
            return
        }

        prefs.edit()
            .putInt("transport", transportSpinner.selectedItemPosition)
            .putString("bridges", bridgeInput.text.toString())
            .apply()

        generation += 1
        val thisGeneration = generation
        activeTransport = type
        isStarting = true
        connectButton.isEnabled = false
        connectButton.text = "Preparing…"
        setStatus(
            "Preparing Tor",
            "Starting the selected transport and validating its local listener."
        )

        io.execute {
            try {
                val port = if (type != TransportType.DIRECT) {
                    AndroidTransportManager.start(this, type)
                } else {
                    0
                }

                if (thisGeneration != generation || isFinishing || isDestroyed) {
                    AndroidTransportManager.stop(type)
                    return@execute
                }

                val torrc = TorConfigBuilder.buildTorrc(type, bridges, port)
                TorService.getTorrc(this).writeText(torrc)

                runOnUiThread {
                    if (thisGeneration != generation || isFinishing || isDestroyed) {
                        AndroidTransportManager.stop(type)
                        return@runOnUiThread
                    }

                    val started = bindService(
                        Intent(this, TorService::class.java),
                        serviceConnection,
                        Context.BIND_AUTO_CREATE
                    )
                    if (started) {
                        isBound = true
                        connectButton.isEnabled = true
                        connectButton.text = "Stop Tor"
                        setStatus(
                            "Starting Tor",
                            "The embedded Tor daemon is verifying its configuration."
                        )
                    } else {
                        isStarting = false
                        connectButton.isEnabled = true
                        connectButton.text = "Start Tor"
                        AndroidTransportManager.stop(type)
                        showFailure("Android could not bind the embedded Tor service.")
                    }
                }
            } catch (error: Exception) {
                AndroidTransportManager.stop(type)
                runOnUiThread {
                    if (thisGeneration == generation && !isDestroyed) {
                        isStarting = false
                        connectButton.isEnabled = true
                        connectButton.text = "Start Tor"
                        showFailure(error.message ?: error.javaClass.simpleName)
                        refreshButtons()
                    }
                }
            }
        }
    }

    private fun stopTor() {
        generation += 1
        isStarting = false
        isConnected = false
        mainHandler.removeCallbacks(bootstrapPoll)

        val oldType = activeTransport
        try {
            torService?.torControlConnection?.shutdownTor("SHUTDOWN")
        } catch (_: Exception) {
        }
        if (isBound) {
            try {
                unbindService(serviceConnection)
            } catch (_: IllegalArgumentException) {
            }
        }
        isBound = false
        torService = null
        io.execute { AndroidTransportManager.stop(oldType) }

        connectButton.isEnabled = true
        connectButton.text = "Start Tor"
        setStatus("Disconnected", "Tor and the selected pluggable transport are stopping.")
        refreshButtons()
        refreshEndpoints()
    }

    private fun requestNewIdentity() {
        val service = torService
        if (!isConnected || service == null) {
            showFailure("Connect to Tor before requesting a new identity.")
            return
        }
        io.execute {
            try {
                service.torControlConnection?.signal("NEWNYM")
                runOnUiThread {
                    setStatus(
                        "Identity request sent",
                        "Tor accepted a NEWNYM request; the public IP may remain the same."
                    )
                }
            } catch (error: Exception) {
                runOnUiThread {
                    showFailure(
                        "Could not request a new identity: " +
                            (error.message ?: "control error")
                    )
                }
            }
        }
    }

    private fun testTorExit() {
        val service = torService
        if (!isConnected || service == null) {
            showFailure("Connect to Tor before testing the exit IP.")
            return
        }
        val port = service.socksPort
        if (port !in 1..65535) {
            showFailure("Tor has not exposed a usable SOCKS port yet.")
            return
        }

        testButton.isEnabled = false
        testButton.text = "Testing…"
        io.execute {
            var connection: HttpURLConnection? = null
            try {
                val proxy = JavaProxy(
                    JavaProxy.Type.SOCKS,
                    InetSocketAddress("127.0.0.1", port)
                )
                connection = URL("https://check.torproject.org/api/ip")
                    .openConnection(proxy) as HttpURLConnection
                connection.connectTimeout = 15000
                connection.readTimeout = 15000
                connection.instanceFollowRedirects = false
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                val result = JSONObject(body)
                val confirmedTor = result.optBoolean("IsTor", false)
                val ip = result.optString("IP", "")
                if (!confirmedTor || ip.isBlank()) {
                    throw IOException(
                        "The endpoint did not confirm a Tor exit. No direct connection was attempted."
                    )
                }
                runOnUiThread {
                    setStatus(
                        "Tor exit verified",
                        "Exit IP: " + ip +
                            ". The request used SOCKS; no direct fallback was attempted."
                    )
                }
            } catch (error: Exception) {
                runOnUiThread {
                    setStatus(
                        "Tor check failed",
                        (error.message ?: "No response") +
                            ". No direct-network fallback was attempted."
                    )
                }
            } finally {
                connection?.disconnect()
                runOnUiThread {
                    if (!isDestroyed) {
                        testButton.isEnabled = true
                        testButton.text = "Test Tor IP"
                    }
                }
            }
        }
    }

    private fun registerStatusReceiver() {
        val filter = IntentFilter().apply {
            addAction(TorService.ACTION_STATUS)
            addAction(TorService.ACTION_ERROR)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(statusReceiver, filter)
        }
        receiverRegistered = true
    }

    private fun updateTransportHint() {
        if (!::transportHint.isInitialized || !::transportSpinner.isInitialized) return
        val type = TransportType.values().getOrElse(transportSpinner.selectedItemPosition) {
            TransportType.DIRECT
        }
        transportHint.text = when (type) {
            TransportType.DIRECT -> "Direct Tor connection; leave the bridge list empty."
            TransportType.OBFS4 -> "Starts bundled obfs4/Lyrebird; use matching obfs4 bridge records."
            TransportType.WEBTUNNEL -> "Starts bundled WebTunnel; use matching WebTunnel bridge records."
            TransportType.MEEK_LITE -> "Starts bundled meek-lite; use matching meek_lite bridge records."
            TransportType.DNSTT -> "Starts bundled DNSTT; use matching dnstt bridge records."
        }
    }

    private fun refreshButtons() {
        if (!::connectButton.isInitialized) return
        identityButton.isEnabled = isConnected
        testButton.isEnabled = isConnected
        connectButton.text = when {
            isStarting -> "Preparing…"
            isBound -> "Stop Tor"
            else -> "Start Tor"
        }
        connectButton.isEnabled = true
    }

    private fun refreshEndpoints() {
        val service = torService
        val socks = try {
            service?.socksPort ?: -1
        } catch (_: Exception) {
            -1
        }
        val http = try {
            service?.httpTunnelPort ?: -1
        } catch (_: Exception) {
            -1
        }
        endpointsView.text = endpointText(socks, http)
    }

    private fun endpointText(socks: Int, http: Int): String {
        val socksLabel = if (socks in 1..65535) socks.toString() else "9050 (default)"
        val httpLabel = if (http in 1..65535) http.toString() else "8118 (default)"
        return "SOCKS  127.0.0.1:" + socksLabel +
            "\nHTTP CONNECT  127.0.0.1:" + httpLabel
    }

    private fun setStatus(title: String, detail: String) {
        if (!::statusView.isInitialized || !::detailView.isInitialized) return
        statusView.text = title
        detailView.text = detail
    }

    private fun showFailure(message: String) {
        setStatus("Needs attention", message)
    }

    private fun card(parent: LinearLayout): LinearLayout {
        val value = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            background = roundedBackground(
                Color.rgb(17, 27, 34),
                Color.rgb(31, 48, 59),
                14
            )
        }
        parent.addView(value, marginParams(bottom = 14))
        return value
    }

    private fun addText(
        parent: LinearLayout,
        value: String,
        size: Float,
        color: Int,
        bold: Boolean,
        bottom: Int
    ): TextView {
        val view = TextView(this).apply {
            text = value
            textSize = size
            setTextColor(color)
            if (bold) setTypeface(typeface, Typeface.BOLD)
            includeFontPadding = true
        }
        parent.addView(view, marginParams(bottom = bottom))
        return view
    }

    private fun makeButton(label: String, color: Int): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
            textSize = 14f
            setTextColor(Color.WHITE)
            backgroundTintList = ColorStateList.valueOf(color)
            minHeight = dp(44)
            stateListAnimator = null
        }
    }

    private fun roundedBackground(fill: Int, stroke: Int, radius: Int): GradientDrawable {
        return GradientDrawable().apply {
            setColor(fill)
            setStroke(dp(1), stroke)
            cornerRadius = dp(radius).toFloat()
        }
    }

    private fun marginParams(bottom: Int = 0, top: Int = 0): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply {
            bottomMargin = dp(bottom)
            topMargin = dp(top)
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    override fun onDestroy() {
        mainHandler.removeCallbacks(bootstrapPoll)
        if (isBound) {
            try {
                torService?.torControlConnection?.shutdownTor("SHUTDOWN")
            } catch (_: Exception) {
            }
            try {
                unbindService(serviceConnection)
            } catch (_: IllegalArgumentException) {
            }
        }
        if (receiverRegistered) {
            try {
                unregisterReceiver(statusReceiver)
            } catch (_: IllegalArgumentException) {
            }
        }
        AndroidTransportManager.stopAll()
        io.shutdownNow()
        super.onDestroy()
    }
}
