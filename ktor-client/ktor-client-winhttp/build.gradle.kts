
apply<test.server.TestServerPlugin>()

plugins {
    id("kotlinx-serialization")
}

kotlin {
    createCInterop("winhttp", windowsTargets()) {
        definitionFile = File(projectDir, "windows/interop/winhttp.def")
    }

    sourceSets {
        windowsMain {
            dependencies {
                //api(project(":ktor-client:ktor-client-core"))
                implementation("io.ktor:ktor-client-core:3.0.2")
                //api(project(":ktor-http:ktor-http-cio"))
                implementation("io.ktor:ktor-http-cio:3.0.2")
            }
        }
        windowsTest {
            dependencies {
                api(project(":ktor-client:ktor-client-plugins:ktor-client-logging"))
                api(project(":ktor-client:ktor-client-plugins:ktor-client-json"))
            }
        }
    }
}
