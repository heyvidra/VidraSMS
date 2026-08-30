import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Read ntfy config from local.properties (gitignored) so the token stays out of source.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) FileInputStream(f).use { load(it) }
}
fun cfg(key: String) = (localProps.getProperty(key) ?: "").trim()

// Values land inside a generated Java string literal, so a stray quote or backslash in a
// token would inject into source rather than fail cleanly.
fun quote(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

// Signing config lives in keystore.properties (gitignored). Absent it, release builds are
// left unsigned rather than failing — so a checkout without the keystore still builds debug.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) FileInputStream(f).use { load(it) }
}
val hasKeystore = keystoreProps.getProperty("storeFile") != null

android {
    namespace = "com.codebox.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.codebox.app"
        minSdk = 26
        targetSdk = 34
        // Bump BOTH on every build so a phone's version is unambiguous — it rides up to the web
        // device card via BuildConfig.VERSION_NAME. versionCode must strictly increase for an
        // in-place update to install; versionName is what a human reads.
        versionCode = 13
        versionName = "1.6"

        buildConfigField("String", "NTFY_URL", quote(cfg("NTFY_URL")))
        buildConfigField("String", "NTFY_TOPIC", quote(cfg("NTFY_TOPIC")))
        buildConfigField("String", "NTFY_TOKEN", quote(cfg("NTFY_TOKEN")))
        buildConfigField("String", "SMS_KEY", quote(cfg("SMS_KEY")))
    }

    signingConfigs {
        if (hasKeystore) create("release") {
            storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
            storePassword = keystoreProps.getProperty("storePassword")
            keyAlias = keystoreProps.getProperty("keyAlias")
            keyPassword = keystoreProps.getProperty("keyPassword")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (hasKeystore) signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures { buildConfig = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    testImplementation("junit:junit:4.13.2")
}
