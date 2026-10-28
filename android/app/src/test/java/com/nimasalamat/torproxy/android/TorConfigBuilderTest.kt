package com.nimasalamat.torproxy.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TorConfigBuilderTest {
    @Test
    fun directModeDisablesBridges() {
        val bridges = TorConfigBuilder.normalizeBridgeLines("", TransportType.DIRECT)
        assertTrue(bridges.isEmpty())
        assertEquals("UseBridges 0\n", TorConfigBuilder.buildTorrc(TransportType.DIRECT, bridges, 0))
    }

    @Test
    fun bridgePrefixIsNormalizedAndTorrcUsesLocalTransportPort() {
        val bridges = TorConfigBuilder.normalizeBridgeLines(
            "Bridge obfs4 192.0.2.1:443 ABCDEF cert=sample iat-mode=0\n# comment",
            TransportType.OBFS4
        )
        assertEquals(1, bridges.size)
        val config = TorConfigBuilder.buildTorrc(TransportType.OBFS4, bridges, 43127)
        assertTrue(config.contains("ClientTransportPlugin obfs4 socks5 127.0.0.1:43127"))
        assertTrue(config.contains("Bridge obfs4 192.0.2.1:443 ABCDEF cert=sample iat-mode=0"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun mismatchedTransportIsRejected() {
        TorConfigBuilder.normalizeBridgeLines(
            "Bridge webtunnel example:443 ABCDEF url=https://example/",
            TransportType.OBFS4
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun emptyBridgeListCannotEnableObfs4() {
        TorConfigBuilder.normalizeBridgeLines("", TransportType.OBFS4)
    }

    @Test(expected = IllegalArgumentException::class)
    fun invalidTransportPortIsRejected() {
        TorConfigBuilder.buildTorrc(
            TransportType.OBFS4,
            listOf("obfs4 192.0.2.1:443 ABCDEF"),
            0
        )
    }
}
