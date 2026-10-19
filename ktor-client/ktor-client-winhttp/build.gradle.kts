/*
 * Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

import ktorbuild.createCInterop

plugins {
    id("ktorbuild.project.library")
    id("kotlinx-serialization")
    id("test-server")
}

// Published under the fork's own coordinates. Scoped to this project so that its
// dependencies still resolve to the upstream io.ktor:*:3.2.1 artifacts.
group = "io.github.xpointtech"
version = "3.2.1.1"

kotlin {
    createCInterop("winhttp", sourceSet = "windows")
    createCInterop("wincert", sourceSet = "windows")

    sourceSets {
        windowsMain.dependencies {
            api(projects.ktorClientCore)
            api(projects.ktorHttpCio)
        }
        windowsTest.dependencies {
            implementation(projects.ktorClientTestBase)
            api(projects.ktorClientLogging)
            api(projects.ktorClientJson)
        }
    }
}
