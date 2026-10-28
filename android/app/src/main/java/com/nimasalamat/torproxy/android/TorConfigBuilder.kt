package com.nimasalamat.torproxy.android

import IPtProxy.IPtProxy

enum class TransportType(
    val label: String,
    val torName: String?,
    val iptProxyName: String?
) {
    DIRECT("Direct", null, null),
    OBFS4("obfs4", "obfs4", IPtProxy.Obfs4),
    WEBTUNNEL("WebTunnel", "webtunnel", IPtProxy.Webtunnel),
    MEEK_LITE("meek_lite", "meek_lite", IPtProxy.MeekLite),
    DNSTT("DNSTT", "dnstt", IPtProxy.Dnstt)
}

object TorConfigBuilder {
    fun normalizeBridgeLines(raw: String, type: TransportType): List<String> {
        if (type == TransportType.DIRECT) {
            require(raw.lineSequence().all { it.isBlank() || it.trim().startsWith("#") }) {
                "Clear the bridge list before using Direct mode."
            }
            return emptyList()
        }

        val lines = raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { line ->
                if (line.startsWith("Bridge ", ignoreCase = true)) {
                    line.substringAfter(' ').trim()
                } else {
                    line
                }
            }
            .toList()

        require(lines.isNotEmpty()) {
            "Add at least one bridge line for " + type.label + "."
        }

        for (line in lines) {
            require(line.length <= 2048) { "A bridge line is too long." }
            require(line.none { it.isISOControl() }) { "Bridge lines cannot contain control characters." }
            val token = line.substringBefore(' ').lowercase()
            require(token == type.torName) {
                "Every bridge line must start with '" + type.torName + "'."
            }
        }
        return lines
    }

    fun buildTorrc(type: TransportType, bridges: List<String>, transportPort: Int): String {
        if (type == TransportType.DIRECT) {
            require(bridges.isEmpty()) { "Direct mode cannot include bridge lines." }
            return "UseBridges 0\n"
        }

        require(transportPort in 1..65535) {
            "The pluggable transport did not provide a valid local port."
        }
        require(bridges.isNotEmpty()) {
            "At least one bridge is required for " + type.label + "."
        }

        val result = StringBuilder()
        result.append("UseBridges 1\n")
        result.append("ClientTransportPlugin ")
            .append(type.torName)
            .append(" socks5 127.0.0.1:")
            .append(transportPort)
            .append('\n')

        for (bridge in bridges) {
            result.append("Bridge ").append(bridge).append('\n')
        }
        return result.toString()
    }
}
