package com.codebox.app

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// Why a send succeeded or failed — as a stable code, not just a sentence.
//
// The whole point of this file is that "发送失败" is not a diagnosis. A send can die in a dozen
// places (permission, AppOps, role, subscription, modem, delivery report, ack) and until each one
// had its own name they all arrived at the web as the same shrug. These codes travel with the ack,
// ride up in the device card, and are what the local test dialog prints — so the same vocabulary
// answers "where did it break" from the phone and from the browser.
object Send {
    const val OK = "SEND_OK"
    const val GENERIC_FAILURE = "SEND_GENERIC_FAILURE"
    const val RADIO_OFF = "SEND_RADIO_OFF"
    const val NULL_PDU = "SEND_NULL_PDU"
    const val NO_SERVICE = "SEND_NO_SERVICE"
    const val TIMEOUT = "SEND_TIMEOUT"
    const val SECURITY_EXCEPTION = "SEND_SECURITY_EXCEPTION"
    const val ILLEGAL_ARGUMENT = "SEND_ILLEGAL_ARGUMENT"
    const val SUBSCRIPTION_UNAVAILABLE = "SEND_SUBSCRIPTION_UNAVAILABLE"
    const val APP_OP_DENIED = "SEND_APP_OP_DENIED"
    const val PERMISSION_DENIED = "SEND_PERMISSION_DENIED"
    const val EMPTY = "SEND_EMPTY"
    const val DECRYPT_FAILED = "OUTBOX_DECRYPT_FAILED"
    const val UNKNOWN = "SEND_UNKNOWN"
}

// One attempt's verdict. attemptId ties the phone's own record, the ack, and the outbox row
// together, so a line on the web can be matched to a line in logcat without guessing by timestamp.
data class SendOutcome(val code: String, val detail: String, val attemptId: String) {
    val ok: Boolean get() = code == Send.OK
    // What the web shows. The code leads because it is the part that is stable across ROMs and
    // languages; the detail after it is whatever the platform actually said.
    fun line(): String = if (ok) "成功 [$attemptId]" else "$code ${sendLabel(code)}｜$detail [$attemptId]"
}

fun newAttemptId(): String {
    val day = SimpleDateFormat("yyyyMMdd", Locale.US).format(Date())
    val rnd = java.util.UUID.randomUUID().toString().replace("-", "").take(8)
    return "SMS-$day-$rnd"
}

// A short Chinese gloss per code, so the web card reads as a sentence and not only as an enum.
fun sendLabel(code: String): String = when (code) {
    Send.OK -> "成功"
    Send.GENERIC_FAILURE -> "通用失败"
    Send.RADIO_OFF -> "射频关闭/飞行模式"
    Send.NULL_PDU -> "空PDU"
    Send.NO_SERVICE -> "无服务/无信号"
    Send.TIMEOUT -> "超时未回执（可能已发出）"
    Send.SECURITY_EXCEPTION -> "系统拒绝（权限/AppOps）"
    Send.ILLEGAL_ARGUMENT -> "参数非法"
    Send.SUBSCRIPTION_UNAVAILABLE -> "指定的SIM不可用"
    Send.APP_OP_DENIED -> "系统静默禁止发短信"
    Send.PERMISSION_DENIED -> "SEND_SMS 未授予"
    Send.EMPTY -> "空号码或内容"
    Send.DECRYPT_FAILED -> "解密失败"
    else -> "未知原因"
}

// The delivery report's result code. Only real public SmsManager constants are listed — a code
// that isn't one of them keeps its number rather than being guessed at.
// ponytail: the classic 1-8 set plus the API-30 modem/network family; anything else falls through
// to SEND_UNKNOWN with the raw number preserved in the detail, so nothing is lost.
fun sendCodeFor(resultCode: Int): String = when (resultCode) {
    SmsManager.RESULT_ERROR_GENERIC_FAILURE -> Send.GENERIC_FAILURE
    SmsManager.RESULT_ERROR_RADIO_OFF, SmsManager.RESULT_RADIO_NOT_AVAILABLE -> Send.RADIO_OFF
    SmsManager.RESULT_ERROR_NULL_PDU -> Send.NULL_PDU
    SmsManager.RESULT_ERROR_NO_SERVICE, SmsManager.RESULT_NETWORK_REJECT,
    SmsManager.RESULT_NETWORK_ERROR -> Send.NO_SERVICE
    SmsManager.RESULT_ERROR_LIMIT_EXCEEDED, SmsManager.RESULT_ERROR_FDN_CHECK_FAILURE,
    SmsManager.RESULT_ERROR_SHORT_CODE_NOT_ALLOWED,
    SmsManager.RESULT_ERROR_SHORT_CODE_NEVER_ALLOWED,
    SmsManager.RESULT_OPERATION_NOT_ALLOWED -> Send.SECURITY_EXCEPTION
    SmsManager.RESULT_INVALID_ARGUMENTS, SmsManager.RESULT_INVALID_SMSC_ADDRESS,
    SmsManager.RESULT_ENCODING_ERROR -> Send.ILLEGAL_ARGUMENT
    else -> Send.UNKNOWN
}

// A raw result code's own name, kept alongside the mapped code so the exact platform value is
// never lost in translation — item 5 of the brief: keep the machine code AND the human detail.
fun resultCodeName(resultCode: Int): String = when (resultCode) {
    android.app.Activity.RESULT_OK -> "RESULT_OK"
    SmsManager.RESULT_ERROR_GENERIC_FAILURE -> "RESULT_ERROR_GENERIC_FAILURE"
    SmsManager.RESULT_ERROR_RADIO_OFF -> "RESULT_ERROR_RADIO_OFF"
    SmsManager.RESULT_ERROR_NULL_PDU -> "RESULT_ERROR_NULL_PDU"
    SmsManager.RESULT_ERROR_NO_SERVICE -> "RESULT_ERROR_NO_SERVICE"
    SmsManager.RESULT_ERROR_LIMIT_EXCEEDED -> "RESULT_ERROR_LIMIT_EXCEEDED"
    SmsManager.RESULT_ERROR_FDN_CHECK_FAILURE -> "RESULT_ERROR_FDN_CHECK_FAILURE"
    SmsManager.RESULT_ERROR_SHORT_CODE_NOT_ALLOWED -> "RESULT_ERROR_SHORT_CODE_NOT_ALLOWED"
    SmsManager.RESULT_ERROR_SHORT_CODE_NEVER_ALLOWED -> "RESULT_ERROR_SHORT_CODE_NEVER_ALLOWED"
    SmsManager.RESULT_RADIO_NOT_AVAILABLE -> "RESULT_RADIO_NOT_AVAILABLE"
    SmsManager.RESULT_NETWORK_REJECT -> "RESULT_NETWORK_REJECT"
    SmsManager.RESULT_INVALID_ARGUMENTS -> "RESULT_INVALID_ARGUMENTS"
    SmsManager.RESULT_INVALID_SMSC_ADDRESS -> "RESULT_INVALID_SMSC_ADDRESS"
    SmsManager.RESULT_OPERATION_NOT_ALLOWED -> "RESULT_OPERATION_NOT_ALLOWED"
    SmsManager.RESULT_NETWORK_ERROR -> "RESULT_NETWORK_ERROR"
    SmsManager.RESULT_ENCODING_ERROR -> "RESULT_ENCODING_ERROR"
    SmsManager.RESULT_MODEM_ERROR -> "RESULT_MODEM_ERROR"
    SmsManager.RESULT_NO_MEMORY -> "RESULT_NO_MEMORY"
    SmsManager.RESULT_INTERNAL_ERROR -> "RESULT_INTERNAL_ERROR"
    SmsManager.RESULT_NO_RESOURCES -> "RESULT_NO_RESOURCES"
    SmsManager.RESULT_CANCELLED -> "RESULT_CANCELLED"
    SmsManager.RESULT_REQUEST_NOT_SUPPORTED -> "RESULT_REQUEST_NOT_SUPPORTED"
    else -> "RESULT_$resultCode"
}

// --- what this phone can actually do right now -------------------------------------------------
// Deliberately NOT one boolean. "默认短信应用" does not imply SEND_SMS, SEND_SMS does not imply the
// AppOp is allowed, and none of them imply a usable subscription — on ColorOS these genuinely come
// apart, which is why a single "可以发送 ✅" was worse than useless. Each gate is reported on its own.

// One SIM, minus anything identifying. The number is deliberately absent: it is PII and adds
// nothing a slot index doesn't already say.
data class SubLite(val subId: Int, val slot: Int, val carrier: String)

data class SmsCaps(
    val sendGranted: Boolean,
    val receiveGranted: Boolean,
    val readPhoneStateGranted: Boolean,
    val readSmsGranted: Boolean,
    val appOpSendSms: String,        // ALLOWED / IGNORED / ERRORED / DEFAULT / MODE_n / UNKNOWN
    val roleHeld: Boolean,
    val roleAvailable: Boolean,
    val defaultSmsPackage: String,   // what the LEGACY api says — may disagree with the role
    val subs: List<SubLite>?,        // null = could not be read at all
) {
    // True when the role and the legacy default-SMS setting disagree. Worth surfacing on its own:
    // it is the state that made an earlier version show "已是默认" while sending was still barred.
    fun roleMismatch(pkg: String): Boolean = roleHeld != (defaultSmsPackage == pkg)
}

private fun granted(ctx: Context, perm: String): Boolean = runCatching {
    ctx.applicationContext.checkSelfPermission(perm) == PackageManager.PERMISSION_GRANTED
}.getOrDefault(false)

// The AppOp behind SEND_SMS. A runtime permission can read as GRANTED while the AppOp is IGNORED,
// in which case the platform accepts the send and silently drops it — no exception, no delivery
// report, nothing. That combination is invisible to checkSelfPermission and is precisely the kind
// of state an OEM permission manager can leave behind, so it gets checked separately.
private fun appOpSendSms(ctx: Context): String = runCatching {
    val ops = ctx.applicationContext.getSystemService(AppOpsManager::class.java) ?: return "UNKNOWN"
    val uid = android.os.Process.myUid()
    val pkg = ctx.applicationContext.packageName
    val mode = if (Build.VERSION.SDK_INT >= 29)
        ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_SEND_SMS, uid, pkg)
    else
        @Suppress("DEPRECATION") ops.checkOpNoThrow(AppOpsManager.OPSTR_SEND_SMS, uid, pkg)
    when (mode) {
        AppOpsManager.MODE_ALLOWED -> "ALLOWED"
        AppOpsManager.MODE_IGNORED -> "IGNORED"
        AppOpsManager.MODE_ERRORED -> "ERRORED"
        AppOpsManager.MODE_DEFAULT -> "DEFAULT"
        else -> "MODE_$mode"
    }
}.getOrDefault("UNKNOWN")

// Active subscriptions, or null when they cannot be read (no READ_PHONE_STATE). null and empty
// mean different things — "we don't know" vs "there is no SIM" — and conflating them is how a
// missing permission got misreported as a missing card.
fun activeSubs(ctx: Context): List<SubLite>? = try {
    ctx.applicationContext.getSystemService(SubscriptionManager::class.java)
        ?.activeSubscriptionInfoList
        ?.map { SubLite(it.subscriptionId, it.simSlotIndex, it.carrierName?.toString()?.trim().orEmpty()) }
} catch (e: SecurityException) {
    null
} catch (e: Exception) {
    null
}

fun smsCapabilities(ctx: Context): SmsCaps {
    val app = ctx.applicationContext
    val roleHeld = runCatching {
        if (Build.VERSION.SDK_INT >= 29)
            app.getSystemService(android.app.role.RoleManager::class.java)
                ?.isRoleHeld(android.app.role.RoleManager.ROLE_SMS) == true
        else android.provider.Telephony.Sms.getDefaultSmsPackage(app) == app.packageName
    }.getOrDefault(false)
    val roleAvailable = runCatching {
        Build.VERSION.SDK_INT < 29 ||
            app.getSystemService(android.app.role.RoleManager::class.java)
                ?.isRoleAvailable(android.app.role.RoleManager.ROLE_SMS) == true
    }.getOrDefault(false)
    return SmsCaps(
        sendGranted = granted(app, android.Manifest.permission.SEND_SMS),
        receiveGranted = granted(app, android.Manifest.permission.RECEIVE_SMS),
        readPhoneStateGranted = granted(app, android.Manifest.permission.READ_PHONE_STATE),
        readSmsGranted = granted(app, android.Manifest.permission.READ_SMS),
        appOpSendSms = appOpSendSms(app),
        roleHeld = roleHeld,
        roleAvailable = roleAvailable,
        defaultSmsPackage = runCatching {
            android.provider.Telephony.Sms.getDefaultSmsPackage(app).orEmpty()
        }.getOrDefault(""),
        subs = activeSubs(app),
    )
}

// A one-line form small enough to ride in the encrypted devinfo blob, so the browser can read the
// same gates the phone sees without anyone having to be holding the handset.
fun capsCompact(c: SmsCaps): String = buildString {
    append(if (c.roleHeld) "role+" else "role-")
    append(if (c.sendGranted) " send+" else " send-")
    append(" op:").append(c.appOpSendSms)
    append(if (c.readPhoneStateGranted) " rps+" else " rps-")
    append(if (c.readSmsGranted) " rsms+" else " rsms-")
    append(" sim:").append(c.subs?.joinToString("/") { "${it.slot + 1}" } ?: "?")
}

// The gates checked before a single byte reaches the modem, as a pure decision so it can be tested
// without a device: null means "nothing is obviously blocking this, try the send".
//
// Order matters. SEND_SMS first because a denied permission is the honest headline; the AppOp
// second because it is the one that lies — the permission reads GRANTED, the send is accepted, and
// the platform drops it silently, producing what would otherwise look like a delivery-report timeout.
fun preflight(caps: SmsCaps, attempt: String): SendOutcome? = when {
    !caps.sendGranted -> SendOutcome(
        Send.PERMISSION_DENIED,
        "SEND_SMS 未授予（默认短信角色：${if (caps.roleHeld) "持有" else "未持有"}）", attempt,
    )
    caps.appOpSendSms == "IGNORED" || caps.appOpSendSms == "ERRORED" -> SendOutcome(
        Send.APP_OP_DENIED,
        "AppOps SEND_SMS=${caps.appOpSendSms}（权限显示已授予，系统仍会静默丢弃）", attempt,
    )
    else -> null
}
