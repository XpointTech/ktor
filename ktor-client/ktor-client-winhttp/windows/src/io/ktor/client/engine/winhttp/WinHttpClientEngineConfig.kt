/*
 * Copyright 2014-2022 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.client.engine.winhttp

import io.ktor.client.engine.*
import io.ktor.http.*

public class WinHttpClientEngineConfig : HttpClientEngineConfig() {

    /**
     * A value indicating whether HTTP 2.0 protocol is enabled in WinHTTP.
     * The default value is true.
     *
     * [Report a problem](https://ktor.io/feedback/?fqname=io.ktor.client.engine.winhttp.WinHttpClientEngineConfig.protocolVersion)
     */
    public var protocolVersion: HttpProtocolVersion = HttpProtocolVersion.HTTP_2_0

    /**
     * A value that allows to set required security protocol versions.
     * By default will be used system setting.
     *
     * [Report a problem](https://ktor.io/feedback/?fqname=io.ktor.client.engine.winhttp.WinHttpClientEngineConfig.securityProtocols)
     */
    public var securityProtocols: WinHttpSecurityProtocol = WinHttpSecurityProtocol.Default

    /**
     * A value that disables TLS verification for outgoing requests.
     *
     * [Report a problem](https://ktor.io/feedback/?fqname=io.ktor.client.engine.winhttp.WinHttpClientEngineConfig.sslVerify)
     */
    public var sslVerify: Boolean = true

    /**
     * Root chain overrides registered via [overrideRootChain].
     */
    public val rootChainOverrides: MutableList<WinHttpRootChainOverride> = mutableListOf()

    /**
     * Validates certificates of hosts matching [hostPattern] against [certificates] instead
     * of the operating system root CA list.
     *
     * A request to a matching host whose certificate does not chain to one of [certificates]
     * fails with [WinHttpSecurityException] after the TLS handshake but before the request
     * line and headers are sent, so no application data reaches the untrusted peer.
     *
     * Hosts that match no registered pattern keep using the system root store.
     *
     * @param hostPattern a glob such as `*.example.com`, matched case-insensitively.
     * @param certificates root CA certificates in base64-encoded DER, with or without PEM armour.
     */
    public fun overrideRootChain(hostPattern: String, vararg certificates: String) {
        rootChainOverrides += WinHttpRootChainOverride(hostPattern, certificates.toList())
    }
}
