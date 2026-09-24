/*
 * Copyright 2014-2022 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.client.engine.winhttp

import io.ktor.client.engine.*
import io.ktor.client.engine.winhttp.internal.*
import io.ktor.http.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

public class WinHttpClientEngineConfig : HttpClientEngineConfig() {

    /**
     * A value that allows to set the preferred HTTP protocol version.
     *
     * [Report a problem](https://ktor.io/feedback/?fqname=io.ktor.client.engine.winhttp.WinHttpClientEngineConfig.protocolVersion)
     */
    public var protocolVersion: HttpProtocolVersion = HttpProtocolVersion.HTTP_1_1

    /**
     * A value that allows you to specify the security protocols
     * that will be used in TLS sessions.
     *
     * [Report a problem](https://ktor.io/feedback/?fqname=io.ktor.client.engine.winhttp.WinHttpClientEngineConfig.securityProtocols)
     */
    public var securityProtocols: WinHttpSecurityProtocol = WinHttpSecurityProtocol.Default

    /**
     * A value indicating whether to verify the server certificate.
     * This option is insecure and should be used for development purposes only.
     *
     * [Report a problem](https://ktor.io/feedback/?fqname=io.ktor.client.engine.winhttp.WinHttpClientEngineConfig.sslVerify)
     */
    public var sslVerify: Boolean = true

    /**
     * Root chain overrides registered via [overrideRootChain].
     */
    internal val rootChainOverrides = mutableListOf<RootChainOverride>()

    /**
     * Instructs the engine to validate the server certificate of every host matching
     * [hostPattern] against the given root CA certificates instead of the OS root store.
     *
     * [hostPattern] supports `*` wildcards, e.g. `*.example.com`. Each element of
     * [rootCaBase64] is a base64-encoded DER certificate (a PEM body without the
     * `BEGIN`/`END CERTIFICATE` markers); line breaks are ignored.
     *
     * When validation fails, the request is completed exceptionally
     * with [WinHttpSecurityException].
     */
    @OptIn(ExperimentalEncodingApi::class)
    public fun overrideRootChain(hostPattern: String, vararg rootCaBase64: String) {
        rootChainOverrides += RootChainOverride(
            hostPatternToRegex(hostPattern),
            rootCaBase64.map { Base64.Mime.decode(it) }
        )
    }
}
