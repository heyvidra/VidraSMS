package com.codebox.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Toast
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

// In-app "online update" for this sideloaded build. There is no Play Store, but the signed APK is
// already hosted on the same worker (KV key "app") and the phone already holds the bearer token, so
// the app can check its version and pull a newer build itself. The one thing Android will NOT allow
// a sideload to do is install silently — so the flow ends at the system package installer, where the
// user taps "安装". Same signing key as the running build, so it is an in-place upgrade.
object Updater {
    private const val PREFS = "upd"
    private const val KEY_LAST = "lastCheck"
    private const val KEY_CODE = "latestCode"
    private const val KEY_NAME = "latestName"
    private const val CHANNEL = "update"
    private const val NOTIF_ID = 8            // 7 = keep-alive, 100+ = SMS; stay clear
    private const val CHECK_EVERY = 6 * 60 * 60 * 1000L
    const val EXTRA_UPDATE = "com.codebox.app.DO_UPDATE"

    // Called from the background poll. Throttled so it costs at most one tiny request every 6h.
    fun maybeCheck(ctx: Context) {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        if (now - p.getLong(KEY_LAST, 0L) < CHECK_EVERY) return
        p.edit().putLong(KEY_LAST, now).apply()
        val meta = fetchMeta() ?: return
        p.edit().putInt(KEY_CODE, meta.first).putString(KEY_NAME, meta.second).apply()
        if (meta.first > BuildConfig.VERSION_CODE) notify(ctx, meta.second)
    }

    private const val KEY_OPEN = "lastOpenCheck"
    private const val OPEN_DEBOUNCE = 2 * 60 * 1000L

    // Called (on a background thread) when the app is opened. Near-always checks — only debounced
    // against rapid resumes — so opening the app surfaces a new version at once instead of waiting
    // out the 6h background cycle, and gives a manual "check now" without an extra button. Returns
    // true if the "update available" state changed, so the caller can re-render.
    fun checkOnOpen(ctx: Context): Boolean {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        if (now - p.getLong(KEY_OPEN, 0L) < OPEN_DEBOUNCE) return false
        p.edit().putLong(KEY_OPEN, now).apply()
        val before = updateAvailable(ctx)
        val meta = fetchMeta() ?: return false
        p.edit().putLong(KEY_LAST, now).putInt(KEY_CODE, meta.first).putString(KEY_NAME, meta.second).apply()
        if (meta.first > BuildConfig.VERSION_CODE) notify(ctx, meta.second)
        return updateAvailable(ctx) != before
    }

    // Manual "check now": always hits the network (ignores both throttles), stores the result and
    // notifies if newer. Returns the latest versionCode, or null if the server couldn't be reached.
    fun forceCheck(ctx: Context): Int? {
        val meta = fetchMeta() ?: return null
        val now = System.currentTimeMillis()
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putLong(KEY_LAST, now).putLong(KEY_OPEN, now)
            .putInt(KEY_CODE, meta.first).putString(KEY_NAME, meta.second).apply()
        if (meta.first > BuildConfig.VERSION_CODE) notify(ctx, meta.second)
        return meta.first
    }

    fun latestCode(ctx: Context): Int =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt(KEY_CODE, 0)

    fun latestName(ctx: Context): String =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_NAME, "").orEmpty()

    fun updateAvailable(ctx: Context): Boolean = latestCode(ctx) > BuildConfig.VERSION_CODE

    // {"code":N,"name":"X"} from GET /api/app?meta=1, first base that answers.
    private fun fetchMeta(): Pair<Int, String>? {
        if (!configured()) return null
        for (base in bases()) {
            val body = httpGet("$base/api/app?meta=1") ?: continue
            return try {
                val o = JSONObject(body)
                o.getInt("code") to o.optString("name")
            } catch (e: Exception) { continue }
        }
        return null
    }

    private fun notify(ctx: Context, name: String) {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "更新", NotificationManager.IMPORTANCE_DEFAULT)
        )
        val open = PendingIntent.getActivity(
            ctx, 1,
            Intent(ctx, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                .putExtra(EXTRA_UPDATE, true),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = Notification.Builder(ctx, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("发现新版本 v$name")
            .setContentText("点击下载并安装")
            .setAutoCancel(true)
            .setContentIntent(open)
            .build()
        runCatching { nm.notify(NOTIF_ID, n) }
    }

    fun canInstall(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O || ctx.packageManager.canRequestPackageInstalls()

    fun openInstallPermission(ctx: Context) {
        runCatching {
            ctx.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
    }

    // Download the APK on a worker thread, then hand it to the system installer on the main thread.
    fun downloadAndInstall(ctx: Context) {
        val app = ctx.applicationContext
        if (!canInstall(app)) {
            Toast.makeText(app, "请先允许「安装未知应用」，然后再点更新", Toast.LENGTH_LONG).show()
            openInstallPermission(app)
            return
        }
        Toast.makeText(app, "正在下载新版本…", Toast.LENGTH_SHORT).show()
        Thread {
            val apk = download(app)
            Handler(Looper.getMainLooper()).post {
                if (apk == null) { Toast.makeText(app, "下载失败，稍后重试", Toast.LENGTH_LONG).show(); return@post }
                val uri = FileProvider.getUriForFile(app, "${app.packageName}.fileprovider", apk)
                val i = Intent(Intent.ACTION_VIEW)
                    .setDataAndType(uri, "application/vnd.android.package-archive")
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                runCatching { app.startActivity(i) }
                    .onFailure { Toast.makeText(app, "无法启动安装器", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private fun download(ctx: Context): File? {
        if (!configured()) return null
        val out = File(ctx.cacheDir, "update.apk")
        for (base in bases()) {
            var conn: HttpURLConnection? = null
            try {
                conn = (URL("$base/api/app").openConnection() as HttpURLConnection).apply {
                    connectTimeout = 20_000; readTimeout = 60_000
                    setRequestProperty("Authorization", "Bearer ${BuildConfig.NTFY_TOKEN}")
                }
                if (conn.responseCode != 200) continue
                val expected = conn.contentLengthLong   // -1 if the server didn't send it
                conn.inputStream.use { input -> out.outputStream().use { input.copyTo(it) } }
                // Only accept a COMPLETE file. A flaky/roaming link can close the socket early:
                // copyTo returns without throwing, leaving a truncated APK that the installer then
                // rejects with a bare "App not installed". Requiring the full Content-Length turns
                // that into a clean retry instead of handing the installer a corrupt package.
                if (out.length() > 0 && (expected <= 0 || out.length() == expected)) return out
                out.delete()
            } catch (e: Exception) {
                // try next base
            } finally {
                conn?.disconnect()
            }
        }
        return null
    }

    private fun httpGet(url: String): String? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000; readTimeout = 15_000
                setRequestProperty("Authorization", "Bearer ${BuildConfig.NTFY_TOKEN}")
            }
            if (conn.responseCode != 200) null
            else conn.inputStream.bufferedReader().use { it.readText() }
        } catch (e: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }
}
