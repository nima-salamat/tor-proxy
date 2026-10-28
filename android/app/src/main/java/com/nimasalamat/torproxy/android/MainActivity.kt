package com.nimasalamat.torproxy.android

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import org.json.JSONObject
import org.torproject.jni.TorService
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val io = Executors.newFixedThreadPool(3)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("torproxy-mobile", Context.MODE_PRIVATE) }
    private val logLines = ArrayDeque<String>()
    private val maxLogLines = 250

    private lateinit var root: FrameLayout
    private lateinit var statusView: TextView
    private lateinit var detailView: TextView
    private lateinit var endpointSummaryView: TextView
    private lateinit var selectedTransportView: TextView
    private lateinit var connectButton: Button
    private lateinit var identityButton: Button
    private lateinit var testButton: Button

    private var drawerOverlay: FrameLayout? = null
    private var sectionOverlay: FrameLayout? = null
    private var logView: TextView? = null
    private var bridgeDraft: String = ""
    private var isBound = false
    private var isStarting = false
    private var isConnected = false
    private var receiverRegistered = false
    @Volatile private var generation = 0
    @Volatile private var torService: TorService? = null
    private var selectedTransport = TransportType.DIRECT
    private var activeTransport = TransportType.DIRECT
    private var lastStatusSignature = ""
    private var lastBootstrapProgress = -1
    private var keepScreenAwake = false

    private enum class Panel(val title: String, val subtitle: String) {
        CONNECTION("Connection", "Choose how Tor connects"),
        BRIDGES("Bridge settings", "Configure bridge records"),
        DIAGNOSTICS("Logs & diagnostics", "Inspect Tor state and local endpoints"),
        SETTINGS("Settings", "App behavior and privacy"),
        ABOUT("About TorProxy", "Version and routing information")
    }

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
            setStatus(
                "Starting Tor",
                "Waiting for Tor to establish its first circuit. No direct-network fallback is used."
            )
            mainHandler.removeCallbacks(bootstrapPoll)
            mainHandler.post(bootstrapPoll)
            refreshButtons()
            refreshEndpoints()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            torService = null
            isBound = false
            isConnected = false
            isStarting = false
            setStatus("Tor service stopped", "The local proxy is unavailable.")
            refreshButtons()
            refreshEndpoints()
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
                            refreshEndpoints()
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

                    if (!isConnected && progress != null && progress != lastBootstrapProgress) {
                        lastBootstrapProgress = progress
                        val title = if (progress >= 100) {
                            "Tor bootstrap complete"
                        } else {
                            "Connecting to Tor · " + progress + "%"
                        }
                        setStatus(
                            title,
                            if (progress >= 100) {
                                "Waiting for a confirmed circuit from Tor."
                            } else {
                                "Tor is building circuits. Some networks need more time or bridges."
                            }
                        )
                    }

                    endpointSummaryView.text = endpointText(socksPort, httpPort)
                    refreshLogPanel()
                    refreshButtons()
                }
            }
            mainHandler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = colorBackground
        window.navigationBarColor = colorBackground
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            window.decorView.systemUiVisibility = 0
        }

        selectedTransport = TransportType.values().getOrElse(
            prefs.getInt("transport", 0)
        ) { TransportType.DIRECT }
        bridgeDraft = prefs.getString("bridges", "").orEmpty()
        keepScreenAwake = prefs.getBoolean("keep_screen_awake", false)
        applyKeepScreenAwake()

        setContentView(buildUi())
        registerStatusReceiver()
        setStatus(
            "Disconnected",
            "Your Tor connection is stopped. Start Tor when you are ready."
        )
        refreshEndpoints()
        appendLog("TorProxy Mobile opened.")
    }

    private val colorBackground = Color.rgb(11, 16, 20)
    private val colorSurface = Color.rgb(17, 27, 34)
    private val colorSurfaceRaised = Color.rgb(23, 36, 44)
    private val colorLine = Color.rgb(38, 56, 67)
    private val colorTextMuted = Color.rgb(163, 178, 188)
    private val colorAccent = Color.rgb(80, 218, 190)
    private val colorAccentButton = Color.rgb(29, 173, 145)
    private val colorWarning = Color.rgb(230, 183, 104)

    private fun buildUi(): View {
        root = FrameLayout(this).apply {
            setBackgroundColor(colorBackground)
        }

        val main = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colorBackground)
        }
        root.addView(main, FrameLayout.LayoutParams(-1, -1))

        val appBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(10), dp(16), dp(10))
            setBackgroundColor(colorBackground)
        }
        val menuButton = TextView(this).apply {
            text = "☰"
            textSize = 25f
            gravity = Gravity.CENTER
            setTextColor(Color.WHITE)
            contentDescription = "Open navigation menu"
            background = roundedBackground(colorSurface, colorLine, 12)
            setOnClickListener { showDrawer() }
        }
        appBar.addView(menuButton, LinearLayout.LayoutParams(dp(46), dp(46)))

        val brand = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), 0, 0, 0)
        }
        addText(brand, "TorProxy", 19f, Color.WHITE, true, 1)
        addText(brand, "MOBILE · TOR ROUTING", 10f, colorAccent, true, 0)
        appBar.addView(
            brand,
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        )

        val statusDot = TextView(this).apply {
            text = if (isConnected) "●" else "○"
            textSize = 15f
            setTextColor(if (isConnected) colorAccent else colorTextMuted)
            gravity = Gravity.CENTER
            contentDescription = "Connection status indicator"
        }
        appBar.addView(statusDot, LinearLayout.LayoutParams(dp(28), dp(32)))
        main.addView(appBar, LinearLayout.LayoutParams(-1, -2))

        val divider = View(this).apply { setBackgroundColor(colorLine) }
        main.addView(divider, LinearLayout.LayoutParams(-1, dp(1)))

        val scroll = ScrollView(this).apply {
            isFillViewport = false
            clipToPadding = false
            setPadding(0, 0, 0, dp(14))
            overScrollMode = View.OVER_SCROLL_IF_CONTENT_SCROLLS
        }
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(22), dp(18), dp(22))
        }
        scroll.addView(page, ScrollView.LayoutParams(-1, -2))
        main.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))

        addText(page, "PRIVATE CONNECTION", 11f, colorAccent, true, 8)
        addText(page, "Your Tor session", 29f, Color.WHITE, true, 8)
        addText(
            page,
            "Start a Tor connection, watch its state, and manage the details from the side menu.",
            14f,
            colorTextMuted,
            false,
            18
        )

        val statusCard = card(page)
        val statusCaption = addText(
            statusCard,
            "CONNECTION STATUS",
            10f,
            colorAccent,
            true,
            8
        )
        statusView = addText(statusCard, "Disconnected", 21f, Color.WHITE, true, 7)
        detailView = addText(
            statusCard,
            "Your Tor connection is stopped.",
            13f,
            colorTextMuted,
            false,
            14
        )
        val statusRule = View(this).apply { setBackgroundColor(colorLine) }
        statusCard.addView(statusRule, LinearLayout.LayoutParams(-1, dp(1)))
        selectedTransportView = addText(
            statusCard,
            "Method · " + selectedTransport.label,
            12f,
            colorTextMuted,
            true,
            8
        )
        endpointSummaryView = addText(
            statusCard,
            "Proxy endpoints are available while Tor is running.",
            12f,
            colorAccent,
            false,
            0
        )
        statusCaption.contentDescription = "Tor connection status"

        connectButton = makeButton("Start Tor", colorAccentButton)
        connectButton.textSize = 16f
        page.addView(connectButton, marginParams(top = 14, bottom = 10))
        connectButton.setOnClickListener {
            if (isBound || isStarting) stopTor() else startTor()
        }

        val actionRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        identityButton = makeButton("New identity", colorSurfaceRaised)
        identityButton.setOnClickListener { requestNewIdentity() }
        testButton = makeButton("Test Tor IP", colorSurfaceRaised)
        testButton.setOnClickListener { testTorExit() }
        actionRow.addView(
            identityButton,
            LinearLayout.LayoutParams(0, dp(48), 1f).apply { marginEnd = dp(6) }
        )
        actionRow.addView(
            testButton,
            LinearLayout.LayoutParams(0, dp(48), 1f).apply { marginStart = dp(6) }
        )
        page.addView(actionRow, marginParams(bottom = 14))

        val menuHint = card(page)
        addText(menuHint, "Manage TorProxy", 16f, Color.WHITE, true, 5)
        addText(
            menuHint,
            "Connection method, bridges, diagnostics, settings, and help are grouped into compact overlay menus.",
            13f,
            colorTextMuted,
            false,
            10
        )
        val openMenuButton = makeButton("Open side menu   →", colorSurfaceRaised)
        openMenuButton.setOnClickListener { showDrawer() }
        menuHint.addView(openMenuButton, LinearLayout.LayoutParams(-1, dp(46)))

        addText(
            page,
            "Note: this build provides local proxy endpoints. It does not yet route every app on the phone.",
            12f,
            colorWarning,
            false,
            0
        )

        return root
    }

    private fun showDrawer() {
        if (drawerOverlay != null || sectionOverlay != null) return

        val overlay = FrameLayout(this).apply {
            setBackgroundColor(Color.argb(160, 0, 0, 0))
            alpha = 0f
            setOnClickListener { closeDrawer() }
        }
        drawerOverlay = overlay
        root.addView(overlay, FrameLayout.LayoutParams(-1, -1))

        val drawer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(20), dp(16), dp(16))
            background = roundedBackground(colorSurface, colorLine, 0)
            elevation = dp(18).toFloat()
            setOnClickListener { }
        }
        val availableWidth = resources.displayMetrics.widthPixels - dp(52)
        val drawerWidth = minOf(dp(340), availableWidth.coerceAtLeast(dp(250)))
        val drawerParams = FrameLayout.LayoutParams(
            drawerWidth,
            ViewGroup.LayoutParams.MATCH_PARENT,
            Gravity.START
        )
        overlay.addView(drawer, drawerParams)

        val heading = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val headingText = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        addText(headingText, "TORPROXY", 11f, colorAccent, true, 4)
        addText(headingText, "Navigation", 24f, Color.WHITE, true, 0)
        heading.addView(headingText, LinearLayout.LayoutParams(0, -2, 1f))

        val close = makeButton("×", colorSurfaceRaised).apply {
            textSize = 25f
            contentDescription = "Close menu"
            setPadding(0, 0, 0, 0)
            minWidth = dp(44)
        }
        close.setOnClickListener { closeDrawer() }
        heading.addView(close, LinearLayout.LayoutParams(dp(44), dp(44)))
        drawer.addView(heading, marginParams(bottom = 18))

        addText(
            drawer,
            "Choose a section",
            12f,
            colorTextMuted,
            false,
            10
        )

        addDrawerItem(
            drawer,
            "⇄",
            Panel.CONNECTION.title,
            Panel.CONNECTION.subtitle,
            Panel.CONNECTION
        )
        addDrawerItem(
            drawer,
            "≋",
            Panel.BRIDGES.title,
            Panel.BRIDGES.subtitle,
            Panel.BRIDGES
        )
        addDrawerItem(
            drawer,
            "⌁",
            Panel.DIAGNOSTICS.title,
            Panel.DIAGNOSTICS.subtitle,
            Panel.DIAGNOSTICS
        )
        addDrawerItem(
            drawer,
            "⚙",
            Panel.SETTINGS.title,
            Panel.SETTINGS.subtitle,
            Panel.SETTINGS
        )
        addDrawerItem(
            drawer,
            "ⓘ",
            Panel.ABOUT.title,
            Panel.ABOUT.subtitle,
            Panel.ABOUT
        )

        val footer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        addText(
            footer,
            "The menu opens over your current screen. Your connection state stays visible in the background.",
            12f,
            colorTextMuted,
            false,
            8
        )
        addText(
            footer,
            "Tor protects only traffic actually routed through Tor.",
            11f,
            colorWarning,
            true,
            0
        )
        drawer.addView(View(this), LinearLayout.LayoutParams(1, 0, 1f))
        drawer.addView(footer, LinearLayout.LayoutParams(-1, -2))

        drawer.translationX = -drawerWidth.toFloat()
        overlay.animate().alpha(1f).setDuration(170).start()
        drawer.animate()
            .translationX(0f)
            .setDuration(220)
            .setInterpolator(DecelerateInterpolator())
            .start()
    }

    private fun addDrawerItem(
        parent: LinearLayout,
        icon: String,
        title: String,
        subtitle: String,
        panel: Panel
    ) {
        val item = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(11), dp(10), dp(11))
            background = roundedBackground(colorSurfaceRaised, colorLine, 12)
            isClickable = true
            isFocusable = true
        }
        val glyph = TextView(this).apply {
            text = icon
            textSize = 22f
            gravity = Gravity.CENTER
            setTextColor(colorAccent)
            background = roundedBackground(colorBackground, colorLine, 10)
        }
        item.addView(glyph, LinearLayout.LayoutParams(dp(44), dp(44)))

        val labels = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), 0, 0, 0)
        }
        addText(labels, title, 15f, Color.WHITE, true, 3)
        addText(labels, subtitle, 11f, colorTextMuted, false, 0)
        item.addView(labels, LinearLayout.LayoutParams(0, -2, 1f))
        parent.addView(item, marginParams(bottom = 8))
        item.setOnClickListener { showSection(panel) }
    }

    private fun closeDrawer() {
        val overlay = drawerOverlay ?: return
        overlay.animate().cancel()
        root.removeView(overlay)
        drawerOverlay = null
    }

    private fun showSection(panelType: Panel) {
        closeDrawer()
        closeSection()

        val overlay = FrameLayout(this).apply {
            setBackgroundColor(Color.argb(178, 0, 0, 0))
            alpha = 0f
            setOnClickListener { closeSection() }
        }
        sectionOverlay = overlay
        root.addView(overlay, FrameLayout.LayoutParams(-1, -1))

        val panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(14), dp(18), dp(16))
            background = roundedBackground(colorBackground, colorLine, 18)
            elevation = dp(24).toFloat()
            setOnClickListener { }
        }
        val width = minOf(resources.displayMetrics.widthPixels - dp(18), dp(420))
        val params = FrameLayout.LayoutParams(
            width.coerceAtLeast(dp(260)),
            ViewGroup.LayoutParams.MATCH_PARENT,
            Gravity.END
        )
        params.setMargins(0, dp(8), dp(8), dp(8))
        overlay.addView(panel, params)

        val top = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val back = makeButton("‹", colorSurfaceRaised).apply {
            textSize = 28f
            contentDescription = "Back to menu"
            setPadding(0, 0, 0, dp(3))
        }
        back.setOnClickListener {
            closeSection()
            showDrawer()
        }
        top.addView(back, LinearLayout.LayoutParams(dp(46), dp(46)))

        val labels = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), 0, dp(8), 0)
        }
        addText(labels, panelType.title, 19f, Color.WHITE, true, 2)
        addText(labels, panelType.subtitle, 11f, colorTextMuted, false, 0)
        top.addView(labels, LinearLayout.LayoutParams(0, -2, 1f))

        val close = makeButton("×", colorSurfaceRaised).apply {
            textSize = 24f
            contentDescription = "Close section"
            setPadding(0, 0, 0, dp(2))
        }
        close.setOnClickListener { closeSection() }
        top.addView(close, LinearLayout.LayoutParams(dp(44), dp(44)))
        panel.addView(top, marginParams(bottom = 12))

        val separator = View(this).apply { setBackgroundColor(colorLine) }
        panel.addView(separator, LinearLayout.LayoutParams(-1, dp(1)))

        val scroll = ScrollView(this).apply {
            clipToPadding = false
            setPadding(0, dp(14), 0, dp(8))
            isFillViewport = false
        }
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, dp(10))
        }
        scroll.addView(body, ScrollView.LayoutParams(-1, -2))
        panel.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))

        when (panelType) {
            Panel.CONNECTION -> buildConnectionPanel(body)
            Panel.BRIDGES -> buildBridgesPanel(body)
            Panel.DIAGNOSTICS -> buildDiagnosticsPanel(body)
            Panel.SETTINGS -> buildSettingsPanel(body)
            Panel.ABOUT -> buildAboutPanel(body)
        }

        overlay.setOnKeyListener { _, keyCode, event ->
            if (keyCode == android.view.KeyEvent.KEYCODE_BACK &&
                event.action == android.view.KeyEvent.ACTION_UP
            ) {
                closeSection()
                true
            } else {
                false
            }
        }

        val startX = if (resources.configuration.layoutDirection == View.LAYOUT_DIRECTION_RTL) {
            -width.toFloat()
        } else {
            width.toFloat()
        }
        panel.translationX = startX
        overlay.animate().alpha(1f).setDuration(170).start()
        panel.animate()
            .translationX(0f)
            .setDuration(230)
            .setInterpolator(DecelerateInterpolator())
            .start()
    }

    private fun closeSection() {
        val overlay = sectionOverlay ?: return
        overlay.animate().cancel()
        root.removeView(overlay)
        sectionOverlay = null
        logView = null
    }

    private fun buildConnectionPanel(parent: LinearLayout) {
        val card = card(parent)
        addText(card, "Connection method", 17f, Color.WHITE, true, 6)
        addText(
            card,
            "Choose direct Tor or an Android-native pluggable transport. Bridges must match the selected method.",
            13f,
            colorTextMuted,
            false,
            12
        )

        val spinner = Spinner(this)
        val adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            TransportType.values().map { it.label }
        )
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinner.adapter = adapter
        spinner.setSelection(selectedTransport.ordinal)
        card.addView(spinner, marginParams(bottom = 8))

        val hint = addText(card, transportDescription(selectedTransport), 12f, colorAccent, false, 10)
        spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parentView: AdapterView<*>?,
                view: View?,
                position: Int,
                id: Long
            ) {
                val chosen = TransportType.values().getOrElse(position) { TransportType.DIRECT }
                hint.text = transportDescription(chosen)
            }

            override fun onNothingSelected(parentView: AdapterView<*>?) = Unit
        }

        val save = makeButton("Save connection method", colorAccentButton)
        save.setOnClickListener {
            selectedTransport = TransportType.values().getOrElse(spinner.selectedItemPosition) {
                TransportType.DIRECT
            }
            prefs.edit().putInt("transport", selectedTransport.ordinal).apply()
            selectedTransportView.text = "Method · " + selectedTransport.label
            setStatus("Connection settings saved", "Method: " + selectedTransport.label + ". Start Tor to apply it.")
            closeSection()
        }
        card.addView(save, LinearLayout.LayoutParams(-1, dp(48)))

        val note = card(parent)
        addText(note, "Bridge records", 15f, Color.WHITE, true, 5)
        addText(
            note,
            "For obfs4, WebTunnel, meek-lite and DNSTT, add matching bridge lines in Bridge settings before connecting.",
            12f,
            colorTextMuted,
            false,
            9
        )
        val openBridges = makeButton("Open bridge settings", colorSurfaceRaised)
        openBridges.setOnClickListener { showSection(Panel.BRIDGES) }
        note.addView(openBridges, LinearLayout.LayoutParams(-1, dp(46)))
    }

    private fun buildBridgesPanel(parent: LinearLayout) {
        val card = card(parent)
        addText(card, "Saved bridge records", 17f, Color.WHITE, true, 6)
        addText(
            card,
            "Paste one bridge per line. Optional leading “Bridge ” is removed automatically. The first token must match the selected connection method.",
            13f,
            colorTextMuted,
            false,
            12
        )

        val edit = EditText(this).apply {
            setText(bridgeDraft)
            hint = "obfs4 host:port fingerprint cert=… iat-mode=0"
            hintTextColor = Color.rgb(104, 120, 131)
            setTextColor(Color.WHITE)
            textSize = 13f
            gravity = Gravity.TOP or Gravity.START
            minLines = 5
            maxLines = 10
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setPadding(dp(12), dp(12), dp(12), dp(12))
            background = roundedBackground(colorSurfaceRaised, colorLine, 10)
        }
        card.addView(edit, marginParams(bottom = 10))

        addText(
            card,
            "Current method: " + selectedTransport.label,
            12f,
            colorAccent,
            true,
            8
        )
        val save = makeButton("Save bridge records", colorAccentButton)
        save.setOnClickListener {
            bridgeDraft = edit.text.toString()
            prefs.edit().putString("bridges", bridgeDraft).apply()
            setStatus("Bridge records saved", "They will be used the next time Tor starts.")
            appendLog("Bridge settings saved locally.")
            closeSection()
        }
        card.addView(save, LinearLayout.LayoutParams(-1, dp(48)))

        val clear = makeButton("Clear bridge records", colorSurfaceRaised)
        clear.setOnClickListener {
            edit.setText("")
            bridgeDraft = ""
            prefs.edit().putString("bridges", "").apply()
            appendLog("Saved bridge records cleared.")
        }
        card.addView(clear, marginParams(top = 8))

        val warning = card(parent)
        addText(warning, "Privacy reminder", 14f, colorWarning, true, 5)
        addText(
            warning,
            "Some bridge records are sensitive and should not be posted publicly. Use bridge records from a source you trust.",
            12f,
            colorTextMuted,
            false,
            0
        )
    }

    private fun buildDiagnosticsPanel(parent: LinearLayout) {
        val endpoints = card(parent)
        addText(endpoints, "Local proxy endpoints", 16f, Color.WHITE, true, 8)
        addText(endpoints, endpointText(
            try { torService?.socksPort ?: -1 } catch (_: Exception) { -1 },
            try { torService?.httpTunnelPort ?: -1 } catch (_: Exception) { -1 }
        ), 13f, colorAccent, true, 10)
        addText(
            endpoints,
            "These listeners are local to this device. Only apps configured to use them send traffic through Tor.",
            12f,
            colorTextMuted,
            false,
            8
        )
        val refresh = makeButton("Refresh status", colorSurfaceRaised)
        refresh.setOnClickListener {
            refreshEndpoints()
            appendLog("Diagnostics refreshed.")
            refreshLogPanel()
        }
        endpoints.addView(refresh, LinearLayout.LayoutParams(-1, dp(44)))

        val logs = card(parent)
        addText(logs, "Event log", 16f, Color.WHITE, true, 6)
        val viewer = TextView(this).apply {
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.rgb(184, 202, 211))
            setPadding(dp(10), dp(10), dp(10), dp(10))
            background = roundedBackground(Color.rgb(7, 12, 16), colorLine, 8)
            text = currentLogs()
            minHeight = dp(140)
            maxHeight = dp(280)
            isVerticalScrollBarEnabled = true
        }
        logView = viewer
        logs.addView(viewer, LinearLayout.LayoutParams(-1, -2))

        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val copy = makeButton("Copy log", colorSurfaceRaised)
        copy.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("TorProxy event log", currentLogs()))
            setStatus("Log copied", "The current local event log was copied to the clipboard.")
        }
        val clear = makeButton("Clear log", colorSurfaceRaised)
        clear.setOnClickListener {
            logLines.clear()
            appendLog("Event log cleared.")
            refreshLogPanel()
        }
        actions.addView(copy, LinearLayout.LayoutParams(0, dp(44), 1f).apply { marginEnd = dp(5) })
        actions.addView(clear, LinearLayout.LayoutParams(0, dp(44), 1f).apply { marginStart = dp(5) })
        logs.addView(actions, marginParams(top = 8))

        val diagnosticNote = card(parent)
        addText(diagnosticNote, "Connection state", 14f, Color.WHITE, true, 5)
        addText(
            diagnosticNote,
            "Tor's bootstrap and circuit status come from the embedded Tor control interface. A failed connectivity check never retries without Tor.",
            12f,
            colorTextMuted,
            false,
            0
        )
    }

    private fun buildSettingsPanel(parent: LinearLayout) {
        val behavior = card(parent)
        addText(behavior, "App behavior", 17f, Color.WHITE, true, 6)
        addText(
            behavior,
            "Keep the screen awake during a Tor session if you want to watch startup and diagnostics without the display turning off.",
            13f,
            colorTextMuted,
            false,
            12
        )
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val label = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        addText(label, "Keep screen awake", 14f, Color.WHITE, true, 4)
        addText(label, "Prevent display sleep while using the app", 11f, colorTextMuted, false, 0)
        row.addView(label, LinearLayout.LayoutParams(0, -2, 1f))
        val toggle = Switch(this).apply {
            isChecked = keepScreenAwake
            buttonTintList = ColorStateList.valueOf(colorAccent)
        }
        toggle.setOnCheckedChangeListener { _, checked ->
            keepScreenAwake = checked
            prefs.edit().putBoolean("keep_screen_awake", checked).apply()
            applyKeepScreenAwake()
            appendLog(if (checked) "Keep screen awake enabled." else "Keep screen awake disabled.")
        }
        row.addView(toggle)
        behavior.addView(row)

        val security = card(parent)
        addText(security, "Privacy and security", 16f, Color.WHITE, true, 6)
        addText(
            security,
            "The Tor daemon and transport state are kept in app-private storage. This application does not expose its SOCKS or control listeners to your LAN.",
            12f,
            colorTextMuted,
            false,
            10
        )
        addText(
            security,
            "This version is a local-proxy app, not a whole-device VPN. It cannot claim that unrelated apps are routed through Tor.",
            12f,
            colorWarning,
            true,
            0
        )

        val reset = makeButton("Reset saved bridge settings", colorSurfaceRaised)
        reset.setOnClickListener {
            bridgeDraft = ""
            prefs.edit().putString("bridges", "").apply()
            setStatus("Bridge settings reset", "Saved bridge records were removed from this device.")
            appendLog("Bridge settings reset from Settings.")
        }
        parent.addView(reset, marginParams(bottom = 8))
    }

    private fun buildAboutPanel(parent: LinearLayout) {
        val about = card(parent)
        addText(about, "TorProxy Mobile", 22f, Color.WHITE, true, 6)
        addText(about, "Android native edition · 0.1.0", 12f, colorAccent, true, 12)
        addText(
            about,
            "The existing desktop application uses PySide6. Android uses native Android UI and platform-compatible Tor libraries instead of trying to package a desktop executable or a Windows/Linux Expert Bundle.",
            13f,
            colorTextMuted,
            false,
            12
        )
        addText(
            about,
            "Embedded components",
            15f,
            Color.WHITE,
            true,
            6
        )
        addText(
            about,
            "• Tor Android: native Tor daemon and Android service\n• jtorctl: Tor control protocol\n• IPtProxy: Android pluggable transports",
            12f,
            colorTextMuted,
            false,
            12
        )

        val routing = card(parent)
        addText(routing, "Routing limitation", 15f, colorWarning, true, 6)
        addText(
            routing,
            "This build exposes local SOCKS and HTTP CONNECT endpoints for compatible apps. Whole-device routing needs a separate Android VPN service and explicit user approval; it is not implemented here yet.",
            12f,
            colorTextMuted,
            false,
            0
        )

        val docs = makeButton("Open project repository", colorSurfaceRaised)
        docs.setOnClickListener {
            try {
                startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(
                    "https://github.com/nima-salamat/tor-proxy/tree/feature/android-tor-native/android"
                )))
            } catch (_: Exception) {
                showFailure("Could not open the repository link.")
            }
        }
        parent.addView(docs, marginParams(bottom = 8))
    }

    private fun startTor() {
        if (isBound || isStarting) return

        val type = selectedTransport
        val rawBridges = prefs.getString("bridges", "").orEmpty()
        val bridges = try {
            TorConfigBuilder.normalizeBridgeLines(rawBridges, type)
        } catch (error: IllegalArgumentException) {
            showFailure(error.message ?: "Invalid bridge configuration.")
            showSection(Panel.BRIDGES)
            return
        }

        prefs.edit()
            .putInt("transport", type.ordinal)
            .putString("bridges", rawBridges)
            .apply()

        generation += 1
        val thisGeneration = generation
        activeTransport = type
        isStarting = true
        isConnected = false
        lastBootstrapProgress = -1
        connectButton.isEnabled = false
        connectButton.text = "Preparing…"
        setStatus(
            "Preparing Tor",
            "Starting " + type.label + " and checking its local listener."
        )
        refreshButtons()

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
                TorService.getTorrc(applicationContext).writeText(torrc)

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
                            "The embedded Tor daemon is checking configuration and building a circuit."
                        )
                        appendLog("Requested Tor startup using " + type.label + ".")
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
        setStatus("Disconnected", "Tor and the selected transport are stopping.")
        appendLog("Requested Tor shutdown.")
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
                    appendLog("Sent a NEWNYM request to Tor.")
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
        appendLog("Started Tor exit IP test through local SOCKS.")
        io.execute {
            var connection: HttpURLConnection? = null
            try {
                val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
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
                        "Exit IP: " + ip + ". The request used SOCKS; no direct fallback was attempted."
                    )
                    appendLog("Tor exit verified. IP: " + ip)
                }
            } catch (error: Exception) {
                runOnUiThread {
                    setStatus(
                        "Tor check failed",
                        (error.message ?: "No response") +
                            ". No direct-network fallback was attempted."
                    )
                    appendLog("Tor exit check failed: " + (error.message ?: error.javaClass.simpleName))
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

    private fun setStatus(title: String, detail: String) {
        if (::statusView.isInitialized) statusView.text = title
        if (::detailView.isInitialized) detailView.text = detail
        if (::selectedTransportView.isInitialized) {
            selectedTransportView.text = "Method · " + selectedTransport.label
        }
        val signature = title + "|" + detail
        if (signature != lastStatusSignature) {
            lastStatusSignature = signature
            appendLog(title + " — " + detail)
        }
    }

    private fun showFailure(message: String) {
        setStatus("Needs attention", message)
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
        connectButton.isEnabled = !isStarting
    }

    private fun refreshEndpoints() {
        if (!::endpointSummaryView.isInitialized) return
        val service = torService
        val socks = try { service?.socksPort ?: -1 } catch (_: Exception) { -1 }
        val http = try { service?.httpTunnelPort ?: -1 } catch (_: Exception) { -1 }
        endpointSummaryView.text = endpointText(socks, http)
        refreshLogPanel()
    }

    private fun endpointText(socks: Int, http: Int): String {
        val socksText = if (socks in 1..65535) {
            "127.0.0.1:" + socks
        } else {
            "Not available"
        }
        val httpText = if (http in 1..65535) {
            "127.0.0.1:" + http
        } else {
            "Not available"
        }
        return "SOCKS  " + socksText + "\nHTTP CONNECT  " + httpText
    }

    private fun appendLog(message: String) {
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        synchronized(logLines) {
            logLines.addLast(timestamp + "  " + message)
            while (logLines.size > maxLogLines) logLines.removeFirst()
        }
        refreshLogPanel()
    }

    private fun currentLogs(): String {
        synchronized(logLines) {
            return if (logLines.isEmpty()) {
                "No events yet."
            } else {
                logLines.joinToString("\n")
            }
        }
    }

    private fun refreshLogPanel() {
        val view = logView ?: return
        view.text = currentLogs()
        if (view.parent is ViewGroup) {
            view.post {
                val parent = view.parent
                if (parent is ScrollView) parent.fullScroll(View.FOCUS_DOWN)
            }
        }
    }

    private fun transportDescription(type: TransportType): String {
        return when (type) {
            TransportType.DIRECT -> "Direct connection to the Tor network. Leave bridge records empty."
            TransportType.OBFS4 -> "Starts Android obfs4/Lyrebird. Add bridge lines beginning with obfs4."
            TransportType.WEBTUNNEL -> "Starts Android WebTunnel. Add matching webtunnel bridge lines."
            TransportType.MEEK_LITE -> "Starts Android meek-lite. Add matching meek_lite bridge lines."
            TransportType.DNSTT -> "Starts Android DNSTT. Add matching dnstt bridge lines."
        }
    }

    private fun applyKeepScreenAwake() {
        if (keepScreenAwake) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
    }

    private fun card(parent: LinearLayout): LinearLayout {
        val value = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(15), dp(15), dp(15), dp(15))
            background = roundedBackground(colorSurface, colorLine, 15)
        }
        parent.addView(value, marginParams(bottom = 13))
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
            setLineSpacing(0f, 1.08f)
        }
        parent.addView(view, marginParams(bottom = bottom))
        return view
    }

    private fun makeButton(label: String, color: Int): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
            textSize = 13f
            setTextColor(Color.WHITE)
            backgroundTintList = ColorStateList.valueOf(color)
            minHeight = dp(44)
            stateListAnimator = null
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        }
    }

    private fun roundedBackground(fill: Int, stroke: Int, radius: Int): GradientDrawable {
        return GradientDrawable().apply {
            setColor(fill)
            if (stroke != Color.TRANSPARENT) setStroke(dp(1), stroke)
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

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    override fun onBackPressed() {
        when {
            sectionOverlay != null -> closeSection()
            drawerOverlay != null -> closeDrawer()
            else -> super.onBackPressed()
        }
    }

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
