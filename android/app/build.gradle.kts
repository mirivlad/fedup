plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "top.mirv.fedup.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "top.mirv.fedup.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.0.1-lab"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    // Rust cargo-ndk packages libfedup_android.so under src/main/jniLibs.
    // A missing native library is a FAIL-CLOSED state, never a fake connection.
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
