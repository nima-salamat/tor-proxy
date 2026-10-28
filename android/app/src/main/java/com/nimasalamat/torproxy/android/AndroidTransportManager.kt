package com.nimasalamat.torproxy.android

import IPtProxy.Controller
import IPtProxy.OnTransportEvents
import android.content.Context
import java.io.File
import java.io.IOException

/**
 * One controller per application process, matching IPtProxy's documented lifecycle.
 */
internal object AndroidTransportManager {
    @Volatile
    private var controller: Controller? = null

    @Synchronized
    fun start(context: Context, type: TransportType): Int {
        val name = type.iptProxyName
            ?: throw IllegalArgumentException("Direct mode does not need a transport.")

        val instance = getController(context)
        instance.start(name, null)

        repeat(40) {
            val port = instance.port(name).toInt()
            if (port in 1..65535) {
                return port
            }
            Thread.sleep(250)
        }

        try {
            instance.stop(name)
        } catch (_: Exception) {
        }
        throw IOException("IPtProxy did not open a local port for " + type.label + ".")
    }

    @Synchronized
    fun stop(type: TransportType) {
        val name = type.iptProxyName ?: return
        try {
            controller?.stop(name)
        } catch (_: Exception) {
        }
    }

    @Synchronized
    fun stopAll() {
        val instance = controller ?: return
        for (type in TransportType.values()) {
            val name = type.iptProxyName ?: continue
            try {
                instance.stop(name)
            } catch (_: Exception) {
            }
        }
    }

    @Synchronized
    private fun getController(context: Context): Controller {
        controller?.let { return it }

        val stateDirectory = File(context.noBackupFilesDir, "iptproxy-state")
        if (!stateDirectory.exists() && !stateDirectory.mkdirs()) {
            throw IOException("Cannot create private transport state directory.")
        }

        val created = Controller(
            stateDirectory.absolutePath,
            true,
            false,
            "INFO",
            object : OnTransportEvents {
                override fun connected(name: String?) = Unit
                override fun error(name: String?, error: Exception?) = Unit
                override fun stopped(name: String?, error: Exception?) = Unit
            }
        )
        controller = created
        return created
    }
}
