/*
 * Copyright 2014-2019 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.network.tls

import io.ktor.network.tls.extensions.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import java.math.*
import java.security.cert.*
import java.security.spec.*
import kotlin.experimental.*

private const val MAX_TLS_FRAME_SIZE = 0x4800

internal suspend fun ByteReadChannel.readTLSRecord(): TLSRecord {
    val type = TLSRecordType.byCode(readByte().toInt() and 0xff)
    val version = readTLSVersion()

    val length = readShortCompatible() and 0xffff
    if (length > MAX_TLS_FRAME_SIZE) throw TLSException("Illegal TLS frame size: $length")

    val packet = readPacket(length)
    return TLSRecord(type, version, packet)
}

@Suppress("DEPRECATION")
internal fun ByteReadPacket.readTLSHandshake(): TLSHandshake = TLSHandshake().apply {
    val typeAndVersion = readInt()
    type = TLSHandshakeType.byCode(typeAndVersion ushr 24)
    val length = typeAndVersion and 0xffffff
    packet = buildPacket {
        writeFully(readBytes(length))
    }
}

@Suppress("DEPRECATION")
internal fun ByteReadPacket.readTLSServerHello(): TLSServerHello {
    val version = readTLSVersion()

    val random = ByteArray(32)
    readFully(random)
    val sessionIdLength = readByte().toInt() and 0xff

    if (sessionIdLength > 32) {
        throw TLSException("sessionId length limit of 32 bytes exceeded: $sessionIdLength specified")
    }

    val sessionId = ByteArray(32)
    readFully(sessionId, 0, sessionIdLength)

    val suite = readShort()

    val compressionMethod = readByte().toShort() and 0xff
    if (compressionMethod.toInt() != 0) {
        throw TLSException(
            "Unsupported TLS compression method $compressionMethod (only null 0 compression method is supported)"
        )
    }

    if (remaining.toInt() == 0) return TLSServerHello(version, random, sessionId, suite, compressionMethod)

    // handle extensions
    val extensionSize = readShort().toInt() and 0xffff

    if (remaining.toInt() != extensionSize) {
        throw TLSException("Invalid extensions size: requested $extensionSize, available $remaining")
    }

    val extensions = mutableListOf<TLSExtension>()
    while (remaining > 0) {
        val type = readShort().toInt() and 0xffff
        val length = readShort().toInt() and 0xffff

        extensions += TLSExtension(
            TLSExtensionType.byCode(type),
            length,
            buildPacket { writeFully(readBytes(length)) }
        )
    }

    return TLSServerHello(version, random, sessionId, suite, compressionMethod, extensions)
}

@Suppress("DEPRECATION")
internal fun ByteReadPacket.readCurveParams(): NamedCurve {
    val type = readByte().toInt() and 0xff
    when (ServerKeyExchangeType.byCode(type)) {
        ServerKeyExchangeType.NamedCurve -> {
            val curveId = readShort()

            return NamedCurve.fromCode(curveId) ?: throw TLSException("Unknown EC id")
        }
        ServerKeyExchangeType.ExplicitPrime -> error("ExplicitPrime server key exchange type is not yet supported")
        ServerKeyExchangeType.ExplicitChar -> error("ExplicitChar server key exchange type is not yet supported")
    }
}

@Suppress("DEPRECATION")
internal fun ByteReadPacket.readTLSCertificate(): List<Certificate> {
    val certificatesChainLength = readTripleByteLength()
    var certificateBase = 0
    val result = ArrayList<Certificate>()
    val factory = CertificateFactory.getInstance("X.509")!!

    while (certificateBase < certificatesChainLength) {
        val certificateLength = readTripleByteLength()
        if (certificateLength > (certificatesChainLength - certificateBase)) {
            throw TLSException("Certificate length is too big")
        }
        if (certificateLength > remaining) throw TLSException("Certificate length is too big")

        val certificate = ByteArray(certificateLength)
        readFully(certificate)
        certificateBase += certificateLength + 3

        val x509 = factory.generateCertificate(certificate.inputStream())
        result.add(x509)
    }

    return result
}

@Suppress("DEPRECATION")
internal fun ByteReadPacket.readECPoint(fieldSize: Int): ECPoint {
    val pointSize = readByte().toInt() and 0xff

    val tag = readByte()
    if (tag != 4.toByte()) throw TLSException("Point should be uncompressed")

    val componentLength = (pointSize - 1) / 2
    if ((fieldSize + 7) ushr 3 != componentLength) throw TLSException("Invalid point component length")

    return ECPoint(
        BigInteger(1, readBytes(componentLength)),
        BigInteger(1, readBytes(componentLength))
    )
}

private suspend fun ByteReadChannel.readTLSVersion() =
    TLSVersion.byCode(readShortCompatible() and 0xffff)

@Suppress("DEPRECATION")
private fun ByteReadPacket.readTLSVersion() =
    TLSVersion.byCode(readShort().toInt() and 0xffff)

@Suppress("DEPRECATION")
internal fun ByteReadPacket.readTripleByteLength(): Int = (readByte().toInt() and 0xff shl 16) or
    (readShort().toInt() and 0xffff)

internal suspend fun ByteReadChannel.readShortCompatible(): Int {
    val first = readByte().toInt() and 0xff
    val second = readByte().toInt() and 0xff

    return (first shl 8) + second
}
