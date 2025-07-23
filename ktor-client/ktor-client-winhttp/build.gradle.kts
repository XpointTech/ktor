/*
 * Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

import ktorbuild.createCInterop

plugins {
    id("ktorbuild.project.library")
    id("kotlinx-serialization")
    id("test-server")
}

kotlin {
    createCInterop("winhttp", sourceSet = "windows")

    sourceSets {
        windowsMain.dependencies {
            implementation("io.ktor:ktor-client-core:3.2.0")
            implementation("io.ktor:ktor-http-cio:3.2.0")
        }
        windowsTest.dependencies {
            implementation(projects.ktorClientTestBase)
            api(projects.ktorClientLogging)
            api(projects.ktorClientJson)
        }
    }
}
