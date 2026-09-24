/*
 * Copyright 2014-2022 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.client.engine.winhttp.internal

import io.ktor.cinterop.winhttp.CCertVerifyCertificateChainPolicySsl
import io.ktor.client.engine.winhttp.*
import io.ktor.utils.io.core.*
import kotlinx.cinterop.*
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
import platform.winhttp.WINHTTP_OPTION_URL
import platform.winhttp.WinHttpQueryOption

/**
 * A single [WinHttpClientEngineConfig.overrideRootChain] registration.
 */
internal class RootChainOverride(
    val hostPattern: Regex,
    val rootCertificates: List<ByteArray>
)

/**
 * Converts a `*`-wildcard host pattern (e.g. `*.example.com`) to a [Regex].
 */
internal fun hostPatternToRegex(pattern: String): Regex =
    pattern.split("*").joinToString(".*") { Regex.escape(it) }.toRegex(RegexOption.IGNORE_CASE)

/**
 * Validates server certificates of hosts registered via
 * [WinHttpClientEngineConfig.overrideRootChain] against the configured root CA
 * certificates, using an exclusive chain engine so the OS root store is ignored.
 *
 * All verification happens on the Kotlin side and reports failures as
 * [WinHttpSecurityException] values, so callers can complete the request's
 * continuation exceptionally instead of throwing inside a WinHTTP callback.
 */
@OptIn(ExperimentalForeignApi::class)
internal class WinHttpCertificateVerifier(overrides: List<RootChainOverride>) : Closeable {

    private class Entry(
        val hostPattern: Regex,
        val rootStore: HCERTSTORE?,
        val chainEngine: COpaquePointer?
    )

    private val entries = overrides.map { override ->
        val store = createMemoryCertStore(override.rootCertificates)
        Entry(override.hostPattern, store, store?.let { createExclusiveChainEngine(it) })
    }

    /**
     * Checks the server certificate of [hRequest] and returns the failure to complete
     * the request with, or `null` when the certificate is trusted or no override
     * matches the request host.
     */
    fun findFailure(hRequest: COpaquePointer): WinHttpSecurityException? {
        if (entries.isEmpty()) return null

        val url = queryRequestUrl(hRequest) ?: return null
        if (!url.startsWith("https://", ignoreCase = true)) return null

        val host = url.substringAfter("://").substringBefore("/").substringBefore(":")
        val entry = entries.firstOrNull { it.hostPattern.matches(host) } ?: return null

        val chainEngine = entry.chainEngine
            ?: return failure(host, "root chain is not available")
        val serverCert = queryServerCertificate(hRequest)
            ?: return failure(host, "server certificate is not available")

        try {
            if (!subjectMatches(serverCert, entry.hostPattern)) {
                return failure(host, "certificate subject does not match")
            }

            val chainContext = buildChainContext(chainEngine, serverCert)
                ?: return failure(host, "unable to build certificate chain")

            try {
                if (!verifySslPolicy(chainContext)) {
                    return failure(host, "certificate chain is not trusted")
                }
            } finally {
                CertFreeCertificateChain(chainContext)
            }
        } finally {
            CertFreeCertificateContext(serverCert)
        }

        return null
    }

    override fun close() {
        entries.forEach { entry ->
            entry.chainEngine?.let { CertFreeCertificateChainEngine(it) }
            entry.rootStore?.let { CertCloseStore(it, 0u) }
        }
    }

    private fun failure(host: String, reason: String) =
        WinHttpSecurityException("Server certificate validation failed for $host: $reason")

    private fun createMemoryCertStore(certificates: List<ByteArray>): HCERTSTORE? {
        val store = CertOpenStore(sz_CERT_STORE_PROV_MEMORY, 0u, 0u, 0u, null) ?: return null
        for (certData in certificates) {
            val ctx = createCertificateContext(certData)
            val added = ctx != null &&
                CertAddCertificateContextToStore(store, ctx, CERT_STORE_ADD_USE_EXISTING.convert(), null) == TRUE
            ctx?.let { CertFreeCertificateContext(it) }
            if (!added) {
                CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG.convert())
                return null
            }
        }
        return store
    }

    private fun createCertificateContext(certificateData: ByteArray): PCCERT_CONTEXT? =
        certificateData.toUByteArray().usePinned {
            CertCreateCertificateContext(X509_ASN_ENCODING.toUInt(), it.addressOf(0), certificateData.size.toUInt())
        }

    private fun createExclusiveChainEngine(rootStore: HCERTSTORE): COpaquePointer? = memScoped {
        val config = alloc<CERT_CHAIN_ENGINE_CONFIG>()
        config.cbSize = sizeOf<CERT_CHAIN_ENGINE_CONFIG>().toUInt()
        config.hExclusiveRoot = rootStore

        val handle = alloc<COpaquePointerVar>()
        if (CertCreateCertificateChainEngine(config.ptr, handle.ptr) == FALSE) return null
        handle.value
    }

    private fun queryRequestUrl(hRequest: COpaquePointer): String? = memScoped {
        val size = alloc<UIntVar>()
        WinHttpQueryOption(hRequest, WINHTTP_OPTION_URL.convert(), null, size.ptr)
        val byteLength = size.value.toInt()
        if (byteLength <= 0) return null

        val buffer = allocArray<ShortVar>(byteLength / 2 + 1)
        if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_URL.convert(), buffer, size.ptr) == FALSE) {
            return null
        }
        buffer.toKStringFromUtf16()
    }

    private fun queryServerCertificate(hRequest: COpaquePointer): PCCERT_CONTEXT? = memScoped {
        val pCert = alloc<PCERT_CONTEXTVar>()
        val size = alloc<UIntVar> { value = sizeOf<PCERT_CONTEXTVar>().toUInt() }
        if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT.convert(), pCert.ptr, size.ptr) == FALSE) {
            return null
        }
        pCert.value
    }

    private fun subjectMatches(serverCert: PCCERT_CONTEXT, hostPattern: Regex): Boolean = memScoped {
        val certName = allocArray<CHARVar>(SUBJECT_NAME_CAPACITY)
        CertGetNameStringA(
            serverCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE.convert(),
            0u,
            null,
            certName,
            SUBJECT_NAME_CAPACITY.convert()
        )
        hostPattern.matches(certName.toKString())
    }

    private fun buildChainContext(
        chainEngine: COpaquePointer,
        serverCert: PCCERT_CONTEXT
    ): PCCERT_CHAIN_CONTEXT? = memScoped {
        val chainPara = alloc<CERT_CHAIN_PARA>()
        chainPara.cbSize = sizeOf<CERT_CHAIN_PARA>().toUInt()

        val chainContext = alloc<PCCERT_CHAIN_CONTEXTVar>()
        if (CertGetCertificateChain(
                chainEngine,
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

    private fun verifySslPolicy(chainContext: PCCERT_CHAIN_CONTEXT?): Boolean = memScoped {
        val policyPara = alloc<CERT_CHAIN_POLICY_PARA>()
        policyPara.cbSize = sizeOf<CERT_CHAIN_POLICY_PARA>().toUInt()

        val policyStatus = alloc<CERT_CHAIN_POLICY_STATUS>()
        policyStatus.cbSize = sizeOf<CERT_CHAIN_POLICY_STATUS>().toUInt()

        CCertVerifyCertificateChainPolicySsl(
            chainContext,
            policyPara.ptr,
            policyStatus.ptr
        ) == TRUE && policyStatus.dwError == 0u
    }

    private companion object {
        private const val SUBJECT_NAME_CAPACITY = 256
    }
}
