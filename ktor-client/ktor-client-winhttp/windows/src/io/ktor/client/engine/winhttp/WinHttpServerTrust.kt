/*
 * Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.client.engine.winhttp

import io.ktor.cinterop.wincert.CCertVerifyCertificateChainPolicySSL
import io.ktor.util.*
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.COpaquePointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.windows.CERT_CHAIN_ENGINE_CONFIG
import platform.windows.CERT_CHAIN_PARA
import platform.windows.CERT_CHAIN_POLICY_PARA
import platform.windows.CERT_CHAIN_POLICY_STATUS
import platform.windows.CERT_CLOSE_STORE_FORCE_FLAG
import platform.windows.CERT_NAME_SIMPLE_DISPLAY_TYPE
import platform.windows.CERT_STORE_ADD_USE_EXISTING
import platform.windows.CHARVar
import platform.windows.CertAddCertificateContextToStore
import platform.windows.CertCloseStore
import platform.windows.CertCreateCertificateChainEngine
import platform.windows.CertCreateCertificateContext
import platform.windows.CertFreeCertificateChain
import platform.windows.CertFreeCertificateChainEngine
import platform.windows.CertFreeCertificateContext
import platform.windows.CertGetCertificateChain
import platform.windows.CertGetNameStringA
import platform.windows.CertOpenStore
import platform.windows.FALSE
import platform.windows.HCERTSTORE
import platform.windows.PCCERT_CHAIN_CONTEXT
import platform.windows.PCCERT_CHAIN_CONTEXTVar
import platform.windows.PCCERT_CONTEXT
import platform.windows.PCERT_CONTEXTVar
import platform.windows.TRUE
import platform.windows.X509_ASN_ENCODING
import platform.windows.sz_CERT_STORE_PROV_MEMORY
import platform.winhttp.WINHTTP_OPTION_SERVER_CERT_CONTEXT
import platform.winhttp.WinHttpQueryOption

/**
 * A root chain override: for any host matching [hostPattern], the server certificate is
 * validated against [certificates] exclusively, instead of against the operating system
 * root CA list.
 *
 * @property hostPattern a glob pattern, e.g. `*.example.com`. Matching is case-insensitive.
 * @property certificates root CA certificates in base64-encoded DER (the body of a PEM
 * file, with or without the `-----BEGIN CERTIFICATE-----` armour).
 */
public class WinHttpRootChainOverride(
    public val hostPattern: String,
    public val certificates: List<String>
)

/**
 * Thrown when a server certificate fails validation against a [WinHttpRootChainOverride].
 *
 * The request is aborted before the request body is sent and before any response is read,
 * so no application data is exchanged with the untrusted peer.
 *
 * @property host the host whose certificate was rejected.
 * @property errorCode the Windows chain policy error code, or `0` when the chain could not
 * be built at all.
 */
public class WinHttpSecurityException(
    public val host: String,
    public val errorCode: UInt,
    message: String
) : Exception(message)

/**
 * Validates server certificates against caller-supplied root chains.
 *
 * All certificate handling for the engine lives in this file so that merges with upstream
 * Ktor stay confined to a couple of call sites.
 */
@OptIn(ExperimentalForeignApi::class)
internal class WinHttpServerTrust(overrides: List<WinHttpRootChainOverride>) {

    private class Pin(val hostMatcher: Regex, val chainEngine: COpaquePointer, val rootStore: HCERTSTORE)

    private val pins: List<Pin> = overrides.mapNotNull { override ->
        val rootStore = createRootStore(override.certificates) ?: return@mapNotNull null
        val chainEngine = createExclusiveChainEngine(rootStore)
        if (chainEngine == null) {
            CertCloseStore(rootStore, CERT_CLOSE_STORE_FORCE_FLAG.convert())
            return@mapNotNull null
        }
        Pin(override.hostPattern.globToRegex(), chainEngine, rootStore)
    }

    /**
     * Verifies the peer certificate of [hRequest] when [host] is covered by an override.
     *
     * Hosts with no matching override are left to WinHTTP's own validation against the
     * system root store and return without any checking.
     *
     * @throws WinHttpSecurityException when the certificate does not chain to the
     * configured roots.
     */
    fun verify(hRequest: COpaquePointer, host: String) {
        val pin = pins.firstOrNull { it.hostMatcher.matches(host) } ?: return

        // Absent on a plain-HTTP connection as well as on a failed handshake. A pinned host
        // that presents no certificate is rejected rather than silently downgraded.
        val serverCert = getServerCertificate(hRequest)
            ?: throw WinHttpSecurityException(host, 0u, "No server certificate presented by $host")

        try {
            val chain = buildChain(pin.chainEngine, serverCert)
                ?: throw WinHttpSecurityException(
                    host,
                    0u,
                    "Server certificate for $host does not chain to a pinned root"
                )
            try {
                val policyError = verifyChainPolicy(chain)
                if (policyError != 0u) {
                    throw WinHttpSecurityException(
                        host,
                        policyError,
                        "Server certificate for $host failed SSL chain policy (error=0x${policyError.toString(16)})"
                    )
                }
                // Matched against every registered pattern, not just the one that selected
                // this pin: a multi-domain certificate may carry a subject from one pinned
                // domain while serving a host covered by another.
                val certName = serverCert.displayName()
                if (pins.none { it.hostMatcher.matches(certName) }) {
                    throw WinHttpSecurityException(
                        host,
                        0u,
                        "Server certificate subject '$certName' is outside the pinned domains"
                    )
                }
            } finally {
                CertFreeCertificateChain(chain)
            }
        } finally {
            CertFreeCertificateContext(serverCert)
        }
    }

    /**
     * Releases the chain engines and root stores. Called when the engine's session closes,
     * by which point no request can still be verifying.
     */
    fun close() {
        pins.forEach {
            CertFreeCertificateChainEngine(it.chainEngine)
            CertCloseStore(it.rootStore, CERT_CLOSE_STORE_FORCE_FLAG.convert())
        }
    }

    private fun createRootStore(certificates: List<String>): HCERTSTORE? {
        val store = CertOpenStore(sz_CERT_STORE_PROV_MEMORY, 0u, 0u, 0u, null) ?: return null
        for (certificate in certificates) {
            val context = createCertificateContext(certificate.pemToDer()) ?: continue
            val added = CertAddCertificateContextToStore(
                store,
                context,
                CERT_STORE_ADD_USE_EXISTING.convert(),
                null
            )
            CertFreeCertificateContext(context)
            if (added == FALSE) {
                CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG.convert())
                return null
            }
        }
        return store
    }

    private fun createCertificateContext(der: ByteArray): PCCERT_CONTEXT? =
        der.toUByteArray().usePinned {
            CertCreateCertificateContext(X509_ASN_ENCODING.toUInt(), it.addressOf(0), der.size.toUInt())
        }

    private fun createExclusiveChainEngine(rootStore: HCERTSTORE): COpaquePointer? = memScoped {
        val config = alloc<CERT_CHAIN_ENGINE_CONFIG>()
        config.cbSize = sizeOf<CERT_CHAIN_ENGINE_CONFIG>().toUInt()
        config.hExclusiveRoot = rootStore

        val handle = alloc<COpaquePointerVar>()
        if (CertCreateCertificateChainEngine(config.ptr, handle.ptr) == FALSE) return null
        handle.value
    }

    private fun getServerCertificate(hRequest: COpaquePointer): PCCERT_CONTEXT? = memScoped {
        val pCert = alloc<PCERT_CONTEXTVar>()
        val size = alloc<UIntVar> { value = sizeOf<PCERT_CONTEXTVar>().toUInt() }
        if (WinHttpQueryOption(
                hRequest,
                WINHTTP_OPTION_SERVER_CERT_CONTEXT.convert(),
                pCert.ptr,
                size.ptr
            ) == FALSE
        ) {
            return null
        }
        pCert.value
    }

    private fun buildChain(engine: COpaquePointer, serverCert: PCCERT_CONTEXT): PCCERT_CHAIN_CONTEXT? = memScoped {
        val chainPara = alloc<CERT_CHAIN_PARA>()
        chainPara.cbSize = sizeOf<CERT_CHAIN_PARA>().toUInt()

        val chainContext = alloc<PCCERT_CHAIN_CONTEXTVar>()
        if (CertGetCertificateChain(
                engine,
                serverCert,
                null,
                null,
                chainPara.ptr,
                0u,
                null,
                chainContext.ptr
            ) == FALSE
        ) {
            return null
        }
        chainContext.value
    }

    /**
     * @return `0` when the chain satisfies the SSL policy, otherwise the policy error code.
     */
    private fun verifyChainPolicy(chain: PCCERT_CHAIN_CONTEXT): UInt = memScoped {
        val policyPara = alloc<CERT_CHAIN_POLICY_PARA>()
        policyPara.cbSize = sizeOf<CERT_CHAIN_POLICY_PARA>().toUInt()

        val policyStatus = alloc<CERT_CHAIN_POLICY_STATUS>()
        policyStatus.cbSize = sizeOf<CERT_CHAIN_POLICY_STATUS>().toUInt()

        val verified = CCertVerifyCertificateChainPolicySSL(
            chain,
            policyPara.ptr,
            policyStatus.ptr
        )
        if (verified != TRUE) UNKNOWN_POLICY_ERROR else policyStatus.dwError
    }

    private fun PCCERT_CONTEXT.displayName(): String = memScoped {
        val name = allocArray<CHARVar>(NAME_BUFFER_SIZE)
        CertGetNameStringA(
            this@displayName,
            CERT_NAME_SIMPLE_DISPLAY_TYPE.convert(),
            0u,
            null,
            name,
            NAME_BUFFER_SIZE.toUInt()
        )
        name.toKString()
    }

    private companion object {
        const val NAME_BUFFER_SIZE = 256

        /** Reported when the policy check itself fails rather than the chain. */
        const val UNKNOWN_POLICY_ERROR = 0xFFFFFFFFu
    }
}

/**
 * Decodes base64-encoded DER, tolerating PEM armour and line breaks.
 */
private fun String.pemToDer(): ByteArray =
    lineSequence()
        .filterNot { it.startsWith("-----") }
        .joinToString("")
        .filterNot { it.isWhitespace() }
        .decodeBase64Bytes()

/**
 * Translates a host glob such as `*.example.com` into a case-insensitive regex.
 */
private fun String.globToRegex(): Regex {
    val pattern = buildString {
        for (char in this@globToRegex) {
            when (char) {
                '*' -> append(".*")
                '.', '\\', '+', '?', '(', ')', '[', ']', '{', '}', '^', '$', '|' -> append('\\').append(char)
                else -> append(char)
            }
        }
    }
    return Regex(pattern, RegexOption.IGNORE_CASE)
}
