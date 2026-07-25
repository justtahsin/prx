plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.prx.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.prx.app"
        minSdk = 24

        // Deliberately below 34. A VPN app that targets 34+ has to declare a
        // foreground service type and satisfy the platform's rules for it;
        // targeting 33 keeps a sideloaded build working on every current
        // Android version without that negotiation. The permissions and the
        // service type are declared anyway, so raising this later is a
        // one-line change.
        targetSdk = 33

        versionCode = 1
        versionName = "0.1.0"

        ndk {
            // What the AAR was built for. Listing them keeps the APK from
            // carrying empty ABI directories.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Signed with the debug key so the APK installs straight away.
            // A personal build has no store to satisfy; swap in a real key
            // if this is ever distributed.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    // The Go core is a ~11 MB native library per architecture, which is most
    // of the package. Splitting by ABI means a phone downloads one of them
    // instead of both; the universal APK stays available for when it is not
    // known which architecture the target is.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a")
            isUniversalApk = true
        }
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }
}

dependencies {
    // The Go client, built with `make aar` in the repository root.
    implementation(files("libs/prxmobile.aar"))

    implementation(platform("androidx.compose:compose-bom:2026.06.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
}
