plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.parda.app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // libsignal-android's AAR metadata requires this (found via a
        // real build failure — `checkDebugAarMetadata`, not assumed).
        isCoreLibraryDesugaringEnabled = true
    }

    defaultConfig {
        applicationId = "com.parda.app"
        // Sub-Phase 4.5B: BluetoothLeAdvertiser (peripheral/advertise role,
        // MeshPlugin.kt) is unreliable before API 26 (Oreo) per Android's
        // own documentation — the default `flutter.minSdkVersion` (21) is
        // too low for the mesh radio backend this phase adds, so it's
        // raised explicitly rather than discovered as a runtime failure
        // on older devices.
        minSdk = maxOf(flutter.minSdkVersion, 26)
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // Sub-Phase 4.5C: required for PlaintextForensicRecoveryTest.kt
        // (androidTest) to run at all.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

dependencies {
    // SignalPlugin.kt's crypto bridge — Signal Foundation's JVM/Android
    // port of libsignal. Pinned to a specific version (this project's
    // existing "pin to a specific audited release; never float this
    // dependency" policy — protocol/Cargo.toml does the same for the
    // Rust libsignal-protocol crate), but **not the same version number**
    // as the Rust crate's pinned git tag (v0.66.0): Maven Central has no
    // `libsignal-android:0.66.0` release (checked — confirmed 0.52.0,
    // 0.73.0, and 0.86.5 exist; 0.66.0 does not), so the Android AAR
    // release cadence doesn't mirror the Rust crate's git tags 1:1. This
    // is not a correctness problem — the Android and Rust builds never
    // talk to each other directly (Android's SignalPlugin.kt performs
    // its own independent X3DH/Double-Ratchet session against the
    // relay's wire-stable JSON envelope format; version parity between
    // the two implementations isn't required for interoperability) — but
    // it is a real divergence from what "pin to the matching version"
    // might imply, stated here rather than left for a reader to assume
    // otherwise.
    implementation("org.signal:libsignal-android:0.52.0")
    // Required by isCoreLibraryDesugaringEnabled above.
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")

    // PersistentSignalStore: EncryptedSharedPreferences, whose master key
    // lives in the Android Keystore. See that class's docs for precisely
    // what this protects and what it does not (the Curve25519 private key
    // itself cannot live inside the Keystore — Android exposes no X25519
    // primitive libsignal's ratchet could use).
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Sub-Phase 4.5C: PlaintextForensicRecoveryTest.kt, an on-device
    // (androidTest) instrumented test — needs a real device/emulator
    // process to read its own /proc/self/mem, which a local (JVM-only)
    // unit test can't do.
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
