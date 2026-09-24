/*
 * Copyright 2014-2022 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.client.engine.winhttp

/**
 * Thrown when the server certificate of a host configured via
 * [WinHttpClientEngineConfig.overrideRootChain] fails validation against
 * the configured root chain.
 */
public class WinHttpSecurityException(message: String) : IllegalStateException(message)
