/*
 * Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

import ktorbuild.createCInterop

plugins {
    id("kotlinx-serialization")
    id("test-server")
}

kotlin {
    createCInterop("winhttp", sourceSet = "windows")

    sourceSets {
        windowsMain {
            dependencies {
                implementation("io.ktor:ktor-client-core:3.1.0")
                implementation("io.ktor:ktor-http-cio:3.1.0")
            }
        }
        windowsTest {
            dependencies {
                implementation(project(":ktor-client:ktor-client-test-base"))
                api(project(":ktor-client:ktor-client-plugins:ktor-client-logging"))
                api(project(":ktor-client:ktor-client-plugins:ktor-client-json"))
            }
        }
    }
}
