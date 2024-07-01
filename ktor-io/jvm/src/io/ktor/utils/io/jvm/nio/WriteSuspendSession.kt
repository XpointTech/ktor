/*
 * Copyright 2014-2024 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.utils.io.jvm.nio

import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.io.*
import kotlinx.io.unsafe.*
import java.nio.*

public class WriteSuspendSession(public val channel: ByteWriteChannel) {
    private val byteBuffer = ByteBuffer.allocate(8192)

    @Suppress("UNUSED_PARAMETER")
    public fun request(count: Int): ByteBuffer? {
        return byteBuffer
    }

    @Suppress("UNUSED_PARAMETER")
    @OptIn(InternalAPI::class)
    public fun tryAwait(count: Int) {
        channel.writeBuffer.writeByteBuffer(byteBuffer)
    }

    @Suppress("UNUSED_PARAMETER")
    public suspend fun written(rc: Int) {
        byteBuffer.flip()
        channel.writeFully(byteBuffer)
        byteBuffer.clear()
        channel.flush()
    }
}

public suspend fun ByteWriteChannel.writeSuspendSession(block: suspend WriteSuspendSession.() -> Unit) {
    try {
        block(WriteSuspendSession(this))
    } finally {
        flush()
    }
}

@OptIn(UnsafeIoApi::class, InternalAPI::class, InternalIoApi::class)
public suspend fun ByteWriteChannel.writeWhile(block: (ByteBuffer) -> Boolean) {
    var done = false

    while (!done) {
        UnsafeBufferOperations.writeToTail(writeBuffer.buffer, 1) { array, start, endExclusive ->
            val buffer = ByteBuffer.wrap(array, start, endExclusive - start)
            done = !block(buffer)
            buffer.position() - start
        }
        flush()
    }
}