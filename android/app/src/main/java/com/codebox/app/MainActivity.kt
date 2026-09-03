package com.codebox.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.BroadcastReceiver
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.provider.Telephony
import java.net.HttpURLConnection
import java.net.URL
import android.text.format.DateUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

// A standalone digit run of 4–8 digits, not part of a decimal or a longer number, so a
// money amount like 12345.67 or an order id like 20260827001 is never taken as a code.
// 4–8 digit run that is not part of a longer number and not part of a decimal. The old form
// excluded a plain "." on either side, which also threw away a code ending a sentence — "验证码
// 998877。" / "code is 998877." — the single commonest real OTP shape, so those messages fell
// through the code filter entirely. Now a trailing/leading dot is fine unless a digit sits on the
// dot's far side (i.e. it is a real decimal like 500.00), which stays excluded.
private val CODE = Regex("(?<!\\d)(?<!\\d\\.)\\d{4,8}(?!\\d)(?!\\.\\d)")

// Chinese OTP texts put the code right after one of these; English ones use "code"/"OTP".
private val KEYWORDS = listOf(
    "验证码", "校验码", "验证代码", "动态码", "动态密码", "安全码", "通行码",
    "口令", "一次性密码", "verification", "code", "otp"
)

// A code is only reported when one of these keywords is present — otherwise a transaction
// SMS ("尾号1234支出500元") would show the account tail as if it were a code. With a keyword,
// pick the digit run closest to it, which is what makes "尾号1234…验证码5678" return 5678.
fun extractCode(body: String): String? {
    val lower = body.lowercase()
    val kw = KEYWORDS.flatMap { k -> Regex(Regex.escape(k)).findAll(lower).map { it.range.first } }
    if (kw.isEmpty()) return null
    val hits = CODE.findAll(body).toList()
    if (hits.isEmpty()) return null
    return hits.minByOrNull { h -> kw.minOf { kotlin.math.abs(h.range.first - it) } }!!.value
}

data class CodeItem(val sender: String, val code: String, val body: String, val date: Long)

// Every captured message, newest first — code ones carry their extracted code for one-tap copy,
// the rest show their body. Filtering to code-only hid ordinary forwarded texts and, worse, hid a
// real code whenever extractCode misfired — so a phone that was capturing and forwarding fine read
// as "最近没有验证码". Reads the app's own local store (filled by the notification listener / SMS
// receiver) rather than content://sms, so no READ_SMS is needed.
fun readRecentCodes(ctx: Context, max: Int = 40): List<CodeItem> {
    val out = ArrayList<CodeItem>()
    for (m in CodeStore.recent(ctx)) {
        if (out.size >= max) break
        out.add(CodeItem(m.sender, extractCode(m.body) ?: "", m.body, m.ts))
    }
    return out
}

class MainActivity : Activity() {

    private lateinit var root: LinearLayout
    private lateinit var headerView: View   // built once and pinned above the scroll area
    // ColorOS drops the AOSP battery whitelist on app update — measured: granted, then gone again
    // after the next install. A banner only helps if it is noticed, so raise the one-tap system
    // dialog instead. One prompt per launch, and never two at once.
    private var askedForBattery = false
    private var night = false

    // Palette, resolved once per create against the current light/dark setting.
    private var bg = 0; private var card = 0; private var ink = 0; private var muted = 0; private var accent = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.hide()   // one title is enough; the custom header below carries it
        night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        if (night) { bg = 0xFF0E1116.toInt(); card = 0xFF161B22.toInt(); ink = 0xFFE6EDF3.toInt(); muted = 0xFF8B949E.toInt(); accent = 0xFF5B8CFF.toInt() }
        else { bg = 0xFFF6F7F9.toInt(); card = 0xFFFFFFFF.toInt(); ink = 0xFF11151C.toInt(); muted = 0xFF6B7280.toInt(); accent = 0xFF2563EB.toInt() }

        // Title pinned outside the ScrollView so it stays put while only the list moves.
        val outer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bg)
        }
        headerView = header()
        outer.addView(headerView)

        val scroll = ScrollView(this)
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), 0, dp(16), dp(24))
        }
        scroll.addView(root)
        outer.addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        setContentView(outer)
        edgeToEdge(outer)

        requestNeededPermissions()
        handleUpdateIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleUpdateIntent(intent)
    }

    // The "发现新版本" notification opens the app with this extra; go straight to download+install.
    private fun handleUpdateIntent(intent: Intent?) {
        if (intent?.getBooleanExtra(Updater.EXTRA_UPDATE, false) == true) {
            intent.removeExtra(Updater.EXTRA_UPDATE)   // don't re-trigger on rotation/resume
            Updater.downloadAndInstall(this)
        }
    }

    // Full-bleed: the background runs behind the status bar and the gesture bar, and the content
    // is pushed clear of them with window insets instead. androidx.core isn't on the classpath,
    // so this uses the platform APIs directly (and the pre-30 deprecated flags below minSdk 30).
    @Suppress("DEPRECATION")
    private fun edgeToEdge(content: View) {
        if (Build.VERSION.SDK_INT >= 30) window.setDecorFitsSystemWindows(false)
        else window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION

        window.statusBarColor = android.graphics.Color.TRANSPARENT
        window.navigationBarColor = android.graphics.Color.TRANSPARENT
        // Otherwise the system paints its own translucent scrim over a transparent nav bar.
        if (Build.VERSION.SDK_INT >= 29) window.isNavigationBarContrastEnforced = false

        // Dark bar icons on the pale light theme, light icons at night.
        if (Build.VERSION.SDK_INT >= 30) {
            val light = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            window.insetsController?.setSystemBarsAppearance(if (night) 0 else light, light)
        } else if (!night) {
            window.decorView.systemUiVisibility = window.decorView.systemUiVisibility or
                View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        }

        // Whatever the bars do, the window itself is our background — on a ROM that ignores
        // setDecorFitsSystemWindows the strip the decor reserves would otherwise show the theme's
        // colour instead of ours.
        window.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(bg))

        // Insets are re-applied on every layout pass, not only when the system dispatches them.
        // Measured on an API 28 phone: an early dispatch reported a top three times the real one
        // (248 against 80) and never came again, so the header stayed stuck 56dp too low. Reading
        // post-layout fixes that; subtracting the decor's own offset also keeps a ROM that ignores
        // setDecorFitsSystemWindows from being counted twice.
        content.setOnApplyWindowInsetsListener { _, insets -> applyInsetPadding(); insets }
        content.viewTreeObserver.addOnGlobalLayoutListener { applyInsetPadding() }
    }

    // Reads the insets and the position the decor actually gave us, and pads by the difference.
    // Runs post-layout, where both numbers are real, and writes only on change so re-laying out
    // from inside a layout listener can't loop.
    @Suppress("DEPRECATION")
    private fun applyInsetPadding() {
        val ins = window.decorView.rootWindowInsets ?: return
        val top: Int; val bottom: Int
        if (Build.VERSION.SDK_INT >= 30) {
            val i = ins.getInsets(
                android.view.WindowInsets.Type.systemBars() or
                    android.view.WindowInsets.Type.displayCutout()
            )
            top = i.top; bottom = i.bottom
        } else {
            top = ins.systemWindowInsetTop; bottom = ins.systemWindowInsetBottom
        }

        // How far the decor has already pushed us clear of each bar. Subtracting it means the
        // padding tops up what is missing rather than blindly adding the full inset again.
        // In-window coordinates, not on-screen: they stay right in split screen and freeform.
        val outer = headerView.parent as? View ?: return
        val offsetTop = IntArray(2).also { outer.getLocationInWindow(it) }[1]
        val offsetBottom = (window.decorView.height - (offsetTop + outer.height)).coerceAtLeast(0)

        val wantTop = dp(10) + (top - offsetTop).coerceAtLeast(0)
        if (headerView.paddingTop != wantTop) headerView.setPadding(dp(20), wantTop, dp(20), dp(14))

        val wantBottom = dp(24) + (bottom - offsetBottom).coerceAtLeast(0)
        if (root.paddingBottom != wantBottom) root.setPadding(dp(16), 0, dp(16), wantBottom)
    }

    // A code captured while the app is open should appear at once. Both capture paths send this
    // internal broadcast after storing a new message, so a single re-render is enough.
    private val newArrived = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) { render() }
    }

    override fun onResume() {
        super.onResume()
        ForwardService.start(this)   // opening the app is a guaranteed-allowed moment to (re)start it
        KeepAliveWorker.schedule(this)   // second, independent path back if the ROM kills our alarms
        // Push a fresh capability report now. Otherwise the web keeps showing whatever the phone
        // last uploaded — up to a poll interval stale — which is how the app could say "可发短信"
        // while the browser still showed the opposite.
        ForwardService.pollNow(this)
        // The default-SMS role is NOT auto-requested. Receiving and forwarding work over the
        // RECEIVE_SMS broadcast without it; the role is only for web→phone sending, which the
        // banner offers on demand. Auto-prompting every open became a loop on ColorOS — it reverts
        // a sideloaded default SMS app within minutes, and re-grabbing it each launch made the
        // phone announce "默认短信应用已切换" over and over. Battery exemption is still nudged, but
        // only once the phone has measurably been suspended.
        if (!askedForBattery && notifAccessGranted() && !batteryExempt() && aliveGaps(this).first > 0) {
            askedForBattery = true
            requestBatteryExempt()
        }
        render()
        // Opening the app is a good moment to check for a new version — do it off the main thread
        // (network) and re-render if one appeared, so the "发现新版本" banner shows without waiting
        // for the background cycle.
        Thread { if (Updater.checkOnOpen(applicationContext)) runOnUiThread { render() } }.start()
        val filter = IntentFilter(NEW_ACTION)
        // Our own broadcast, so NOT_EXPORTED is correct (and forwardNow sets the package).
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(newArrived, filter, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(newArrived, filter)
    }

    override fun onPause() {
        super.onPause()
        runCatching { unregisterReceiver(newArrived) }
    }

    override fun onRequestPermissionsResult(rc: Int, p: Array<out String>, r: IntArray) {
        super.onRequestPermissionsResult(rc, p, r)
        // A denied SEND_SMS with no rationale left to show means the system will not ask again;
        // repeating the request would do nothing at all, so hand the user the settings page.
        if (rc == 3 && !canSendSms() && !shouldShowRequestPermissionRationale(Manifest.permission.SEND_SMS)) {
            Toast.makeText(this, "请在权限页里把「短信」改为允许", Toast.LENGTH_LONG).show()
            openAppSettings()
        }
        render()
    }

    // Two runtime permissions to ask for: POST_NOTIFICATIONS (33+) and READ_PHONE_STATE (only so
    // a chosen SIM slot maps to its subscription when sending; sending still works without it,
    // just on the default SIM). Notification access is a special Settings grant, not requestable.
    private fun requestNeededPermissions() {
        val want = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) want += Manifest.permission.POST_NOTIFICATIONS
        if (checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED)
            want += Manifest.permission.READ_PHONE_STATE
        if (want.isNotEmpty()) requestPermissions(want.toTypedArray(), 1)
    }

    // SEND_SMS is deliberately NOT in the automatic request above. Asking for it on every launch
    // backfired: one "拒绝" tap marks it user-denied, and a user decision outranks the automatic
    // grant that comes with the default-SMS role — so the app ends up unable to send even after
    // holding the role, and some ROMs then stop offering it as a default-SMS candidate at all.
    // It is only ever asked for when the user taps the banner, and once permanently denied the
    // only way back is the settings page, so go there instead of re-asking into the void.
    private fun requestSendSms() {
        if (canSendSms()) { render(); return }
        if (shouldShowRequestPermissionRationale(Manifest.permission.SEND_SMS)) {
            requestPermissions(arrayOf(Manifest.permission.SEND_SMS), 3)
        } else {
            // Either never asked (the request just works) or permanently denied (it silently
            // fails). Ask first; onRequestPermissionsResult sends the user to settings if the
            // dialog never appeared.
            requestPermissions(arrayOf(Manifest.permission.SEND_SMS), 3)
        }
    }

    private fun openAppSettings() {
        runCatching {
            startActivity(
                Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(android.net.Uri.parse("package:$packageName"))
            )
        }.onFailure { Toast.makeText(this, "请到 设置 → 应用 → 验证码 → 权限 里允许「短信」", Toast.LENGTH_LONG).show() }
    }

    private fun canSendSms(): Boolean =
        checkSelfPermission(Manifest.permission.SEND_SMS) == PackageManager.PERMISSION_GRANTED

    // Becoming the default SMS app is what makes SEND_SMS grantable, so ask for it the moment
    // the role dialog returns rather than waiting for the next launch.
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        // No SEND_SMS request here either — taking the role grants it by itself when the user
        // has not previously denied it, and asking again is what created the denial in the first place.
        if (requestCode == 2) ForwardService.pollNow(this)   // tell the web at once
        render()
    }

    // Default SMS app — the role that exempts the app from the hard SMS-permission restriction,
    // so SEND_SMS actually works. On 29+ the authoritative source is RoleManager.isRoleHeld:
    // the legacy secure setting getDefaultSmsPackage() reads can stay null even while the role
    // is held (seen on emulators), which would leave the banner stuck on forever.
    private fun defaultSmsApp(): Boolean {
        if (Build.VERSION.SDK_INT >= 29) {
            val rm = getSystemService(android.app.role.RoleManager::class.java)
            if (rm != null) return rm.isRoleHeld(android.app.role.RoleManager.ROLE_SMS)
        }
        return Telephony.Sms.getDefaultSmsPackage(this) == packageName
    }

    private fun requestDefaultSms() {
        if (Build.VERSION.SDK_INT >= 29) {
            val rm = getSystemService(android.app.role.RoleManager::class.java)
            if (rm != null && rm.isRoleAvailable(android.app.role.RoleManager.ROLE_SMS)) {
                // MUST be startActivityForResult: RequestRoleActivity reads getCallingPackage(),
                // which is null under a plain startActivity → it aborts with "Package name cannot
                // be null" and the dialog just flashes shut. onResume re-renders on return.
                runCatching {
                    startActivityForResult(rm.createRequestRoleIntent(android.app.role.RoleManager.ROLE_SMS), 2)
                }
                return
            }
        }
        @Suppress("DEPRECATION")
        runCatching {
            startActivity(
                Intent(Telephony.Sms.Intents.ACTION_CHANGE_DEFAULT)
                    .putExtra(Telephony.Sms.Intents.EXTRA_PACKAGE_NAME, packageName)
            )
        }.onFailure { Toast.makeText(this, "请到 设置 → 默认应用 → 短信 里选择本应用", Toast.LENGTH_LONG).show() }
    }

    // "Notification access" — the special access this app relies on. Read straight from the
    // system setting; any listener component under our package counts.
    private fun notifAccessGranted(): Boolean {
        val flat = android.provider.Settings.Secure.getString(contentResolver, "enabled_notification_listeners") ?: return false
        return flat.split(":").any { android.content.ComponentName.unflattenFromString(it)?.packageName == packageName }
    }

    private fun openNotifAccess() {
        runCatching { startActivity(Intent(android.provider.Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) }
            .onFailure { Toast.makeText(this, "请到 设置 → 通知使用权 里开启本应用", Toast.LENGTH_LONG).show() }
    }

    // The AOSP Doze whitelist. Handles stock/Pixel/most ROMs; MIUI/EMUI "autostart" is a
    // separate, undocumented layer that no stable intent reaches — the status hint covers it.
    private fun batteryExempt(): Boolean =
        getSystemService(android.os.PowerManager::class.java)?.isIgnoringBatteryOptimizations(packageName) ?: true

    private fun requestBatteryExempt() {
        // The direct one-tap dialog; fall back to the settings list, then to a manual hint.
        val direct = Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            android.net.Uri.parse("package:$packageName"))
        runCatching { startActivity(direct) }.onFailure {
            runCatching { startActivity(Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
                .onFailure { Toast.makeText(this, "请到 设置 → 电池 里，把本应用设为不受限制", Toast.LENGTH_LONG).show() }
        }
    }

    // The AOSP battery whitelist is not the whole story on Chinese ROMs: Huawei/Honor keep a
    // separate "应用启动管理", Xiaomi an "自启动" list, OPPO/vivo their own. Measured on two phones
    // with identical AOSP settings — the OPPO stayed online with the screen off, the Huawei went
    // silent within half an hour. No public API reports or requests it, so the best that can be
    // done is to take the user to the right screen and say what to turn on.
    // Each vendor calls this something different and hides it somewhere else, so the wording has
    // to match the phone in the user's hand — telling an OPPO owner to open 应用启动管理 sends them
    // looking for a menu ColorOS does not have.
    private data class OemStep(val where: String, val what: String, val intent: Intent?)

    private fun oemAutostart(): OemStep? {
        val maker = Build.MANUFACTURER.orEmpty().lowercase()
        val (where, what, candidates) = when {
            // Two separate switches on EMUI, and the second one is the one that actually bites
            // here: the SMS receiver clearly still runs while frozen (the message lands in the
            // phone's own inbox) but the upload fails, which is background network being cut,
            // not the process being stopped. Autostart alone does not restore it.
            maker.contains("huawei") || maker.contains("honor") -> Triple(
                "手机管家→应用启动管理",
                "关「自动管理」·三项全开·联网应用允许后台数据/WLAN",
                listOf(
                    "com.huawei.systemmanager/.startupmgr.ui.StartupNormalAppListActivity",
                    "com.huawei.systemmanager/.optimize.process.ProtectActivity",
                    "com.huawei.systemmanager/.appcontrol.activity.StartupAppControlActivity",
                ),
            )
            maker.contains("xiaomi") || maker.contains("redmi") || maker.contains("poco") -> Triple(
                "安全中心→自启动",
                "开自启动·最近任务里下拉加锁",
                listOf("com.miui.securitycenter/com.miui.permcenter.autostart.AutoStartManagementActivity"),
            )
            maker.contains("oppo") || maker.contains("realme") || maker.contains("oneplus") -> Triple(
                "设置→电池→应用耗电管理",
                "允许「后台运行」和「自启动」",
                listOf(
                    "com.coloros.safecenter/.permission.startup.StartupAppListActivity",
                    "com.coloros.safecenter/.startupapp.StartupAppListActivity",
                    "com.oppo.safe/.permission.startup.StartupAppListActivity",
                    "com.coloros.oppoguardelf/com.coloros.powermanager.fuelgaue.PowerUsageModelActivity",
                ),
            )
            maker.contains("vivo") || maker.contains("iqoo") -> Triple(
                "i管家→自启动",
                "允许自启动·允许后台高耗电",
                listOf("com.vivo.permissionmanager/.activity.BgStartUpManagerActivity"),
            )
            maker.contains("meizu") -> Triple(
                "手机管家→后台管理",
                "允许后台运行",
                listOf("com.meizu.safe/.permission.SmartBGActivity"),
            )
            else -> Triple("", "", emptyList())
        }
        if (where.isEmpty()) return null
        val intent = candidates
            .map { Intent().setComponent(android.content.ComponentName.unflattenFromString(it)) }
            .firstOrNull { packageManager.resolveActivity(it, 0) != null }
        return OemStep(where, what, intent)
    }

    private fun render() {
        root.removeAllViews()   // headerView lives outside the scroll area and is never rebuilt

        // In-app update: shown first when a newer build is known (learned by the background poll).
        // Tapping downloads the signed APK and hands it to the system installer — the user still
        // confirms the install there; Android does not allow a sideload to install silently.
        if (Updater.updateAvailable(this)) {
            root.addView(banner("发现新版本 v${Updater.latestName(this)}，点此下载并安装。") {
                Updater.downloadAndInstall(this)
            })
        }

        // A nudge, NOT a gate. Notification access is only one of two capture paths — the default
        // SMS app / RECEIVE_SMS broadcast captures without it — so returning here hid the whole
        // code list on a phone that was in fact storing and forwarding codes. It only genuinely
        // needs granting for missed calls, and for SMS when we are not the default SMS app.
        if (!notifAccessGranted()) {
            root.addView(banner("未开「通知使用权」，可能漏收未接来电/短信。点此开启。") { openNotifAccess() })
        }
        // Non-blocking: the app works now, but Doze may kill the listener later. Nudge until fixed.
        if (!batteryExempt()) {
            root.addView(banner("建议关电池优化，防止被系统杀掉。点此设置。") { requestBatteryExempt() })
        }
        // Shown even when the AOSP exemption is already granted, because on these ROMs it is not
        // sufficient — there is no way to query the OEM list, so it can only ever be a reminder.
        oemAutostart()?.let { step ->
            val tail = if (step.intent != null) "点此前往。" else ""
            root.addView(banner("省电策略会杀后台，需：${step.what}。$tail") {
                val i = step.intent
                if (i == null) Toast.makeText(this, step.where, Toast.LENGTH_LONG).show()
                else runCatching { startActivity(i) }
                    .onFailure { Toast.makeText(this, step.where, Toast.LENGTH_LONG).show() }
            })
        }
        // Outbound path. Gate on the actual ability to send — SEND_SMS — NOT on the default-SMS
        // role: an adb `-g` install holds SEND_SMS under an installer exemption and can send
        // without ever being default, so nagging it to "设为默认" was wrong and, on ColorOS, fed a
        // set-default → revert loop. Only when SEND_SMS is missing do we nudge, and then toward
        // whichever route can grant it: taking the role (the sideload path) or the permission
        // directly (once the role or an adb exemption has made it grantable).
        if (!canSendSms()) {
            if (!defaultSmsApp()) {
                root.addView(banner("发短信需设为默认短信应用。点此设置。") { requestDefaultSms() })
            } else {
                root.addView(banner("未授予发短信权限，发信会失败。点此授权。") { requestSendSms() })
            }
        }
        val items = try { readRecentCodes(this) } catch (e: Exception) { emptyList() }
        if (items.isEmpty()) {
            root.addView(hint("最近没有短信。", tappable = false) {})
            return
        }
        for (it in items) root.addView(codeCard(it))
    }

    private fun header(): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            // Horizontal padding matches the cards' dp(16) + their old dp(4) inner offset, so the
            // title still lines up with them now that it sits outside the scrolling list.
            setPadding(dp(20), dp(10), dp(20), dp(14))
            // Whole header is the touch target (much bigger than the glyphs), and long-press
            // reveals the forwarding status — kept out of the main view on purpose.
            setOnLongClickListener { showStatus(); true }
        }
        val title = TextView(this).apply {
            text = "验证码"; textSize = 22f; setTextColor(ink); typeface = Typeface.DEFAULT_BOLD
        }
        val sub = TextView(this).apply {
            text = "点按数字复制"; textSize = 12.5f; setTextColor(muted)
            setPadding(dp(10), dp(6), 0, 0)
        }
        val check = TextView(this).apply {
            text = "检查更新"; textSize = 13f; setTextColor(accent)
            setPadding(dp(8), dp(6), 0, 0)
            setOnClickListener { checkForUpdate() }
        }
        row.addView(title, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
        row.addView(sub, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        row.addView(check, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
        return row
    }

    // Explicit "check for updates" — hits the server now (no waiting on the 6h cycle), with a toast
    // for each outcome. On finding a newer build the banner appears via render().
    private fun checkForUpdate() {
        Toast.makeText(this, "正在检查更新…", Toast.LENGTH_SHORT).show()
        Thread {
            val code = Updater.forceCheck(applicationContext)
            runOnUiThread {
                when {
                    code == null -> Toast.makeText(this, "检查失败，请稍后重试", Toast.LENGTH_SHORT).show()
                    code > BuildConfig.VERSION_CODE -> {
                        render()
                        Toast.makeText(this, "发现新版本 v" + Updater.latestName(this), Toast.LENGTH_SHORT).show()
                    }
                    else -> Toast.makeText(this, "已是最新版本（v" + BuildConfig.VERSION_NAME + "）", Toast.LENGTH_SHORT).show()
                }
            }
        }.start()
    }

    private fun codeCard(item: CodeItem): View {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(card, dp(14))
            setPadding(dp(15), dp(13), dp(15), dp(14))
        }
        (box.layoutParams ?: LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)).let {
            box.layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { bottomMargin = dp(10) }
        }

        val meta = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        meta.addView(TextView(this).apply {
            text = item.sender; textSize = 13.5f; setTextColor(ink); typeface = Typeface.DEFAULT_BOLD
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        meta.addView(TextView(this).apply {
            text = DateUtils.getRelativeTimeSpanString(item.date, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS)
            textSize = 12f; setTextColor(muted)
        })
        box.addView(meta)

        if (item.code.isNotEmpty()) {
            val code = TextView(this).apply {
                text = item.code; textSize = 26f; setTextColor(accent)
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                letterSpacing = 0.08f
                setPadding(0, dp(6), 0, dp(4))
                setOnClickListener { copy(item.code) }
            }
            box.addView(code)
            box.addView(TextView(this).apply {
                text = item.body; textSize = 13.5f; setTextColor(muted); maxLines = 2
            })
        } else {
            // No code: the message body IS the content, so give it room rather than a tiny muted
            // caption under a code that isn't there.
            box.addView(TextView(this).apply {
                text = item.body; textSize = 15f; setTextColor(ink); maxLines = 6
                setPadding(0, dp(6), 0, 0)
            })
        }
        return box
    }

    private fun copy(code: String) {
        getSystemService(ClipboardManager::class.java)
            ?.setPrimaryClip(ClipData.newPlainText("code", code))
        Toast.makeText(this, "已复制 $code", Toast.LENGTH_SHORT).show()
    }

    private fun hint(text: String, tappable: Boolean, onTap: () -> Unit): View =
        TextView(this).apply {
            this.text = text; textSize = 14f; setTextColor(muted); gravity = Gravity.CENTER
            setPadding(dp(20), dp(60), dp(20), dp(60))
            if (tappable) setOnClickListener { onTap() }
        }

    // A small accent-tinted, tappable notice that sits above the list without blocking it.
    private fun banner(text: String, onTap: () -> Unit): View {
        val tv = TextView(this).apply {
            this.text = text; textSize = 13.5f
            setTextColor(if (night) 0xFFCFE0FF.toInt() else 0xFF1D4ED8.toInt())
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = rounded(if (night) 0xFF16233D.toInt() else 0xFFEFF4FF.toInt(), dp(12))
            setOnClickListener { onTap() }
        }
        tv.layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { bottomMargin = dp(10) }
        return tv
    }

    // The forwarding side, reachable by long-pressing the title. Deliberately not a
    // first-class screen — the app looks like a code helper, not a forwarder.
    // --- keep-alive checklist ------------------------------------------------------------------
    private data class OemItem(val key: String, val label: String, val intent: Intent?)

    // The per-vendor allow-list toggles, as a checklist. None can be read back (no API exposes an
    // OEM autostart/lock state), so each carries a manual "done" flag the user ticks, plus a
    // best-effort deep-link to the right settings screen.
    private fun oemKeepalive(): List<OemItem> {
        val maker = Build.MANUFACTURER.orEmpty().lowercase()
        fun link(vararg comps: String): Intent? = comps
            .map { Intent().setComponent(android.content.ComponentName.unflattenFromString(it)) }
            .firstOrNull { packageManager.resolveActivity(it, 0) != null }
        return when {
            maker.contains("huawei") || maker.contains("honor") -> listOf(
                OemItem("hw_auto", "应用启动管理：关「自动管理」，三项全开", link(
                    "com.huawei.systemmanager/.startupmgr.ui.StartupNormalAppListActivity",
                    "com.huawei.systemmanager/.optimize.process.ProtectActivity")),
                OemItem("hw_net", "休眠时始终保持网络连接（设置→电池→更多电池设置）", null),
                OemItem("hw_data", "应用联网：移动数据 + WLAN 都开（手机管家→流量管理）", null),
                OemItem("lock", "最近任务里锁定本应用卡片", null),
            )
            maker.contains("oppo") || maker.contains("realme") || maker.contains("oneplus") -> listOf(
                OemItem("op_auto", "应用耗电管理：允许「后台运行」「自启动」", link(
                    "com.coloros.safecenter/.permission.startup.StartupAppListActivity",
                    "com.coloros.safecenter/.startupapp.StartupAppListActivity",
                    "com.oppo.safe/.permission.startup.StartupAppListActivity")),
                OemItem("lock", "最近任务里锁定本应用卡片", null),
            )
            maker.contains("xiaomi") || maker.contains("redmi") || maker.contains("poco") -> listOf(
                OemItem("mi_auto", "自启动：打开", link("com.miui.securitycenter/com.miui.permcenter.autostart.AutoStartManagementActivity")),
                OemItem("lock", "最近任务里锁定本应用卡片", null),
            )
            maker.contains("vivo") || maker.contains("iqoo") -> listOf(
                OemItem("vv_auto", "自启动 + 后台高耗电：允许", link("com.vivo.permissionmanager/.activity.BgStartUpManagerActivity")),
                OemItem("lock", "最近任务里锁定本应用卡片", null),
            )
            maker.contains("meizu") -> listOf(
                OemItem("mz_auto", "后台管理：允许后台运行", link("com.meizu.safe/.permission.SmartBGActivity")),
                OemItem("lock", "最近任务里锁定本应用卡片", null),
            )
            else -> listOf(OemItem("lock", "最近任务里锁定本应用卡片", null))
        }
    }

    private fun kaDone(key: String) =
        getSharedPreferences("keepalive", MODE_PRIVATE).getBoolean(key, false)
    private fun kaSet(key: String, v: Boolean) =
        getSharedPreferences("keepalive", MODE_PRIVATE).edit().putBoolean(key, v).apply()

    private fun goButton(text: String, onGo: () -> Unit): TextView =
        TextView(this).apply {
            this.text = text; textSize = 13f; setTextColor(accent)
            setPadding(dp(10), dp(5), dp(10), dp(5))
            background = rounded(if (night) 0x22FFFFFF else 0x11000000, dp(8))
            setOnClickListener { onGo() }
        }

    // A checklist row: a tap-to-toggle ✅/◻️ done-mark, the instruction, and an optional deep-link.
    // Re-forward the phone's existing inbox (see backfillInbox). Needs the default-SMS role: READ_SMS
    // is only granted with it, so a non-default phone cannot read the system inbox at all.
    private fun syncExisting() {
        if (!isDefaultSmsApp(this)) {
            Toast.makeText(this, "需先设为默认短信应用，才能读取系统短信", Toast.LENGTH_LONG).show()
            return
        }
        Toast.makeText(this, "正在同步…", Toast.LENGTH_SHORT).show()
        val app = applicationContext
        Thread {
            val r = runCatching { backfillInbox(app) }.getOrDefault(intArrayOf(0, 0, -1))
            runOnUiThread {
                Toast.makeText(
                    this,
                    if (r[2] < 0) "同步失败（无法读取系统短信）"
                    else "同步完成：补发 ${r[0]} 条，已有 ${r[1]} 条，失败 ${r[2]} 条",
                    Toast.LENGTH_LONG,
                ).show()
                render()
            }
        }.start()
    }

    // A ✅/◻️ row bound to an app preference (kaRow is bound to the OEM checklist keys instead).
    private fun prefRow(label: String, get: () -> Boolean, set: (Boolean) -> Unit): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(5), 0, dp(5))
        }
        val chk = TextView(this).apply { textSize = 15f; setPadding(0, 0, dp(9), 0); text = if (get()) "✅" else "◻️" }
        val tv = TextView(this).apply { text = label; textSize = 13.5f; setTextColor(ink) }
        val toggle = { val nv = !get(); set(nv); chk.text = if (nv) "✅" else "◻️" }
        chk.setOnClickListener { toggle() }
        tv.setOnClickListener { toggle() }
        row.addView(chk); row.addView(tv, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        return row
    }

    private fun kaRow(item: OemItem): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(5), 0, dp(5))
        }
        val chk = TextView(this).apply {
            textSize = 15f; setPadding(0, 0, dp(9), 0)
            text = if (kaDone(item.key)) "✅" else "◻️"
        }
        val label = TextView(this).apply { text = item.label; textSize = 13.5f; setTextColor(ink) }
        val toggle = { val nv = !kaDone(item.key); kaSet(item.key, nv); chk.text = if (nv) "✅" else "◻️" }
        chk.setOnClickListener { toggle() }
        label.setOnClickListener { toggle() }
        row.addView(chk); row.addView(label, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        item.intent?.let { i ->
            row.addView(goButton("去设置") {
                runCatching { startActivity(i) }
                    .onFailure { Toast.makeText(this, "请手动到系统设置里开启", Toast.LENGTH_LONG).show() }
            })
        }
        return row
    }

    // An actionable status row for the two settings the app CAN open directly (notif access, battery).
    private fun linkRow(label: String, onGo: () -> Unit): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(0, dp(4), 0, dp(4))
        }
        row.addView(TextView(this).apply { text = label; textSize = 13.5f; setTextColor(accent) },
            LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        row.addView(goButton("前往", onGo))
        return row
    }

    private fun showStatus() {
        val access = notifAccessGranted()
        val ok = configured()

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(10), dp(22), dp(4))
        }
        // Measured first, so the battery line below can agree with it (and with the web card).
        val (gaps, worst) = aliveGaps(this)

        // Capability, phrased the way the rest of the app now is. Receiving works over ANY armed
        // capture path — notification access, the default-SMS role, or the RECEIVE_SMS broadcast —
        // so it is not tied to notification access alone; sending needs SEND_SMS. Neither requires
        // the default-SMS role on its own. Same logic as the web card's 可接收转发.
        val canReceive = access || defaultSmsApp() ||
            checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
        content.addView(statusLine(
            if (canReceive) "✅ 能收短信/转发" else "❌ 收不到短信——请开「通知使用权」或设为默认短信应用"
        ))
        // Missed-call capture is the one thing that genuinely needs notification access (it is read
        // from the dialer's notification, not a broadcast), so call it out when it is off.
        if (!access) content.addView(statusLine("◻️ 未开通知使用权：收不到未接来电", muted))
        content.addView(statusLine(
            if (canSendSms()) "✅ 发短信：权限已授予" else "❌ 发短信：需设为默认短信应用（以取得发送权限）"
        ))
        if (!defaultSmsApp()) {
            content.addView(statusLine("◻️ 非默认短信应用（收发不受影响；仅写入系统短信库需要）", muted))
        }
        // Battery: measurement outranks the setting. Not being exempt is only a real fault once the
        // phone has actually been suspended; on a measurably-fine phone it is a grey footnote, not a
        // red ❌ — same rule as the web device card.
        content.addView(statusLine(
            when {
                batteryExempt() -> "✅ 已不受电池优化限制"
                gaps > 0 -> "⚠️ 电池优化未关，且后台被挂起过——建议关闭"
                else -> "◻️ 电池优化未关（实测运行正常）"
            },
            when { batteryExempt() -> ink; gaps > 0 -> 0xFFEF4444.toInt(); else -> muted },
        ))
        // Jumps for the two settings the app can open directly.
        if (!access) content.addView(linkRow("开启通知使用权") { openNotifAccess() })
        if (!batteryExempt()) content.addView(linkRow("关闭电池优化（Doze 白名单）") { requestBatteryExempt() })
        content.addView(statusLine(if (ok) "✅ 同步目标已配置" else "❌ 未配置同步目标（见 local.properties）"))
        // The honest answer to "did the OEM autostart setting take?": not whether it is set, which
        // no API exposes, but whether the phone actually kept running.
        content.addView(statusLine(
            if (gaps == 0) "✅ 近 24 小时后台未被中断（最长间隔 ${worstGapMinutes(this)} 分钟）"
            // Say what it costs, not just that it happened: a suspended background delays the
            // outbox and the online dot, while incoming SMS arrive by broadcast either way.
            else "⚠️ 近 24 小时后台被挂起 $gaps 次（最长 $worst 分钟）——期间网页发信会延迟；收短信不受影响",
            if (gaps == 0) ink else 0xFFEF4444.toInt(),
        ))

        // The OEM allow-list — the strongest defence against a force-stop, and the one part no API
        // can set or read, so it is a manual checklist: deep-link to each screen, tick when done.
        // Android 11+ "remove permissions if app isn't used": on a background forwarder the system
        // decides it is "unused" and quietly strips SEND_SMS — the "过一会又没权限了". ColorOS hides
        // or renames the switch, so detect it here and deep-link straight to the page instead of
        // sending anyone menu-hunting. Only meaningful from API 30.
        if (Build.VERSION.SDK_INT >= 30) {
            val exempt = runCatching { packageManager.isAutoRevokeWhitelisted }.getOrDefault(true)
            content.addView(statusLine("—— 权限自动重置（安卓 11+）——", muted, top = dp(14)))
            if (exempt) {
                content.addView(statusLine("✅ 已关闭「未使用时移除权限」", muted, top = dp(4)))
            } else {
                content.addView(statusLine("❌ 「未使用时移除权限」开着——会悄悄收走发短信权限", 0xFFDC2626.toInt(), top = dp(4)))
                content.addView(linkRow("去关闭（直达该页面）") {
                    runCatching {
                        startActivity(
                            Intent(Intent.ACTION_AUTO_REVOKE_PERMISSIONS, android.net.Uri.parse("package:$packageName"))
                        )
                    }.onFailure {
                        Toast.makeText(this, "请到 设置→应用→验证码→权限 最底部关闭「未使用时移除权限」", Toast.LENGTH_LONG).show()
                    }
                })
            }
        }
        content.addView(statusLine("—— 厂商保活（开好后打勾）——", muted, top = dp(14)))
        for (it in oemKeepalive()) content.addView(kaRow(it))
        // Mirroring into the system SMS DB is what handed the stock Messages app a reason to be
        // opened — and a non-default stock SMS app reclaims the role on every launch. Off by
        // default; here so it can be turned back on if this phone must also read as a normal phone.
        content.addView(statusLine("—— 系统短信 ——", muted, top = dp(14)))
        content.addView(prefRow("抄送到系统「信息」App（会让它抢回默认，默认关）", { mirrorSms(this) }, { setMirrorSms(this, it) }))
        // Backfill: messages that arrived while this app was not capturing (no notification access,
        // not default, killed, or wiped by a clear-data) sit in the system inbox unforwarded.
        content.addView(linkRow("同步手机已有短信到网页（最近 50 条）") { syncExisting() })

        if (ok) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dp(12), 0, 0)
            }
            // Show the primary domain's main label (+N when there are backup bases).
            val bs = bases()
            val host = (bs.firstOrNull() ?: "").substringAfter("://").substringBefore("/").substringBefore(".")
            val label = if (bs.size > 1) "$host +${bs.size - 1}" else host
            val target = TextView(this).apply {
                text = "目标：$label"; textSize = 14f; setTextColor(ink)
                maxLines = 1; ellipsize = android.text.TextUtils.TruncateAt.MIDDLE
            }
            // ● turns green when the server answered, red when it couldn't be reached.
            val dot = TextView(this).apply {
                text = "●"; textSize = 20f; setTextColor(muted); setPadding(dp(12), 0, dp(12), 0)
            }
            val refresh = TextView(this).apply {
                text = "↻"; textSize = 30f; setTextColor(accent)
                setPadding(dp(6), dp(2), dp(4), dp(6))
                background = rounded(if (night) 0x22FFFFFF else 0x11000000, dp(10))  // visible tap target
            }
            row.addView(target, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            row.addView(dot); row.addView(refresh)
            content.addView(row)

            fun check() {
                dot.setTextColor(muted)   // grey = checking
                pingTarget { reachable -> dot.setTextColor(if (reachable) 0xFF22C55E.toInt() else 0xFFEF4444.toInt()) }
            }
            refresh.setOnClickListener { check() }
            check()   // probe once as soon as the dialog opens
        }

        content.addView(statusLine("若延迟，请到系统设置关闭本应用的电池优化并锁定后台。", muted, top = dp(12)))
        // The checklist makes this taller than a phone screen — wrap it so it scrolls instead of
        // clipping the top rows.
        val scroll = ScrollView(this).apply { addView(content) }
        // After changing a ROM setting the old counters say nothing about whether it helped, so
        // offer a clean slate rather than making the user wait out the 24h window.
        AlertDialog.Builder(this).setTitle("保活检查").setView(scroll)
            .setPositiveButton("好", null)
            .setNeutralButton("重新测量") { _, _ ->
                resetHealth(this)
                Toast.makeText(this, "已清零，从现在开始重新统计", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun statusLine(text: String, color: Int = ink, top: Int = dp(3)): TextView =
        TextView(this).apply {
            this.text = text; textSize = 14.5f; setTextColor(color); setPadding(0, top, 0, dp(3))
        }

    // Any HTTP status back from our domain means the whole path (DNS → TLS → Cloudflare)
    // is up; only a network/TLS failure — no signal, GFW block, server down — is red.
    private fun pingTarget(onResult: (Boolean) -> Unit) {
        Thread {
            // Green if ANY base answers — the forwarding path only needs one reachable door.
            val ok = bases().any { base ->
                try {
                    (URL(base).openConnection() as HttpURLConnection).run {
                        requestMethod = "HEAD"; connectTimeout = 6000; readTimeout = 6000
                        instanceFollowRedirects = false
                        val code = responseCode   // throws on connect/TLS failure
                        disconnect()
                        code in 100..599
                    }
                } catch (e: Exception) { false }
            }
            runOnUiThread { onResult(ok) }
        }.start()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun rounded(color: Int, radius: Int) = GradientDrawable().apply {
        setColor(color); cornerRadius = radius.toFloat()
        if (!night) setStroke(dp(1), 0x11000000)
    }
}
