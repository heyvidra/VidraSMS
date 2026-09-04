package com.codebox.app

import android.app.Activity
import android.telephony.SmsManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

// Covers the decision logic of the send path — the parts that can be tested without a handset.
// Anything that talks to SmsManager, AppOpsManager or SubscriptionManager needs a real device (or
// Robolectric, which is not a dependency here); the point of preflight/sendCodeFor/doneRing being
// pure functions is that the *decisions* are checkable on the JVM even so.
class SendPathTest {

    private fun caps(
        send: Boolean = true,
        op: String = "ALLOWED",
        role: Boolean = true,
        subs: List<SubLite>? = listOf(SubLite(1, 0, "中国电信")),
        defaultPkg: String = "com.codebox.app",
        readSms: Boolean = true,
    ) = SmsCaps(
        sendGranted = send, receiveGranted = true, readPhoneStateGranted = subs != null,
        readSmsGranted = readSms, appOpSendSms = op, roleHeld = role, roleAvailable = true,
        defaultSmsPackage = defaultPkg, subs = subs,
    )

    // --- pre-flight gates -----------------------------------------------------------------------

    @Test fun healthyPhonePassesPreflight() {
        assertNull(preflight(caps(), "A"))
    }

    @Test fun missingSendPermissionIsNamedAsSuch() {
        val r = preflight(caps(send = false), "A")!!
        assertEquals(Send.PERMISSION_DENIED, r.code)
    }

    // The case the old code could not see: permission GRANTED, AppOp IGNORED. The platform accepts
    // the send and drops it — no exception, no delivery report — so it used to surface as a
    // 60-second timeout with no explanation.
    @Test fun grantedPermissionWithIgnoredAppOpIsAppOpDenied() {
        val r = preflight(caps(send = true, op = "IGNORED"), "A")!!
        assertEquals(Send.APP_OP_DENIED, r.code)
        assertTrue(r.detail.contains("IGNORED"))
    }

    @Test fun erroredAppOpAlsoBlocks() {
        assertEquals(Send.APP_OP_DENIED, preflight(caps(op = "ERRORED"), "A")!!.code)
    }

    // MODE_DEFAULT means "no explicit rule" — for a default SMS app that is normal, not a block.
    @Test fun defaultAppOpIsNotTreatedAsDenial() {
        assertNull(preflight(caps(op = "DEFAULT"), "A"))
    }

    @Test fun permissionIsReportedBeforeAppOps() {
        assertEquals(Send.PERMISSION_DENIED, preflight(caps(send = false, op = "IGNORED"), "A")!!.code)
    }

    // --- role vs legacy default -----------------------------------------------------------------

    @Test fun roleAndLegacyDefaultDisagreeing_isDetected() {
        assertTrue(caps(role = true, defaultPkg = "com.android.mms").roleMismatch("com.codebox.app"))
        assertTrue(caps(role = false, defaultPkg = "com.codebox.app").roleMismatch("com.codebox.app"))
        assertEquals(false, caps(role = true, defaultPkg = "com.codebox.app").roleMismatch("com.codebox.app"))
    }

    // --- delivery-report result codes -----------------------------------------------------------

    @Test fun mapsPublicResultCodesToStableNames() {
        assertEquals(Send.GENERIC_FAILURE, sendCodeFor(SmsManager.RESULT_ERROR_GENERIC_FAILURE))
        assertEquals(Send.RADIO_OFF, sendCodeFor(SmsManager.RESULT_ERROR_RADIO_OFF))
        assertEquals(Send.NULL_PDU, sendCodeFor(SmsManager.RESULT_ERROR_NULL_PDU))
        assertEquals(Send.NO_SERVICE, sendCodeFor(SmsManager.RESULT_ERROR_NO_SERVICE))
        assertEquals(Send.RADIO_OFF, sendCodeFor(SmsManager.RESULT_RADIO_NOT_AVAILABLE))
        assertEquals(Send.NO_SERVICE, sendCodeFor(SmsManager.RESULT_NETWORK_REJECT))
        assertEquals(Send.SECURITY_EXCEPTION, sendCodeFor(SmsManager.RESULT_OPERATION_NOT_ALLOWED))
        assertEquals(Send.ILLEGAL_ARGUMENT, sendCodeFor(SmsManager.RESULT_INVALID_SMSC_ADDRESS))
    }

    // An unrecognised code must not be silently renamed into a wrong one — it stays UNKNOWN and
    // the raw number survives in resultCodeName so nothing is lost.
    @Test fun unknownResultCodeKeepsItsNumber() {
        assertEquals(Send.UNKNOWN, sendCodeFor(9999))
        assertEquals("RESULT_9999", resultCodeName(9999))
        assertEquals("RESULT_OK", resultCodeName(Activity.RESULT_OK))
        assertEquals("RESULT_ERROR_NO_SERVICE", resultCodeName(SmsManager.RESULT_ERROR_NO_SERVICE))
    }

    @Test fun everyCodeHasAHumanLabel() {
        listOf(
            Send.OK, Send.GENERIC_FAILURE, Send.RADIO_OFF, Send.NULL_PDU, Send.NO_SERVICE,
            Send.TIMEOUT, Send.SECURITY_EXCEPTION, Send.ILLEGAL_ARGUMENT,
            Send.SUBSCRIPTION_UNAVAILABLE, Send.APP_OP_DENIED, Send.PERMISSION_DENIED,
            Send.EMPTY, Send.DECRYPT_FAILED,
        ).forEach { assertNotEquals("no label for $it", "未知原因", sendLabel(it)) }
        assertEquals("未知原因", sendLabel(Send.UNKNOWN))
    }

    // --- outcome formatting ---------------------------------------------------------------------

    @Test fun outcomeLineCarriesCodeAndAttemptId() {
        val ok = SendOutcome(Send.OK, "1段全部回执成功", "SMS-20260904-abcd1234")
        assertTrue(ok.ok)
        assertTrue(ok.line().contains("SMS-20260904-abcd1234"))

        val bad = SendOutcome(Send.NO_SERVICE, "RESULT_ERROR_NO_SERVICE(4)", "SMS-20260904-ffff0000")
        assertEquals(false, bad.ok)
        assertTrue(bad.line().contains(Send.NO_SERVICE))          // machine-readable
        assertTrue(bad.line().contains("无服务"))                   // and human-readable
        assertTrue(bad.line().contains("RESULT_ERROR_NO_SERVICE")) // raw platform name preserved
    }

    @Test fun attemptIdsAreUniqueAndShaped() {
        val a = newAttemptId()
        assertNotEquals(a, newAttemptId())
        assertTrue(a, Regex("^SMS-\\d{8}-[0-9a-f]{8}$").matches(a))
    }

    // --- the "already handled" ring -------------------------------------------------------------
    // Guards the duplicate-SMS case: a send that succeeded but whose ack was lost must be re-acked,
    // never re-sent, when the server hands the row back after its claim window.

    @Test fun ringRemembersAHandledRow() {
        val r = doneRingPut("", 25L, Send.OK)
        assertEquals(Send.OK, doneRingGet(r, 25L))
        assertNull(doneRingGet(r, 26L))
    }

    @Test fun ringUpdatesRatherThanDuplicatingAnId() {
        val r = doneRingPut(doneRingPut("", 25L, Send.TIMEOUT), 25L, Send.OK)
        assertEquals(Send.OK, doneRingGet(r, 25L))
        assertEquals(1, r.split(",").size)
    }

    @Test fun ringIsBoundedAndDropsTheOldest() {
        var r = ""
        for (i in 1L..60L) r = doneRingPut(r, i, Send.OK, max = 40)
        assertEquals(40, r.split(",").size)
        assertNull("oldest should have aged out", doneRingGet(r, 1L))
        assertEquals(Send.OK, doneRingGet(r, 60L))
    }

    // A prefix must not match: id 2 is not id 25.
    @Test fun ringDoesNotMatchOnPrefix() {
        val r = doneRingPut("", 25L, Send.OK)
        assertNull(doneRingGet(r, 2L))
        assertNull(doneRingGet(r, 5L))
    }

    @Test fun emptyRingIsSafe() {
        assertNull(doneRingGet("", 1L))
        assertNull(doneRingGet(",,", 1L))
    }

    // --- HTTP failure classification ------------------------------------------------------------
    // Every one of these used to be the same `null`, which is why "命令没到手机" and "手机没在轮询"
    // could not be told apart from the web.

    @Test fun httpFailuresKeepTheirIdentity() {
        assertEquals("DNS", classify(java.net.UnknownHostException("x"), false))
        assertEquals("TLS", classify(javax.net.ssl.SSLHandshakeException("x"), true))
        assertEquals("CONNECT_TIMEOUT", classify(java.net.SocketTimeoutException("x"), false))
        assertEquals("READ_TIMEOUT", classify(java.net.SocketTimeoutException("x"), true))
        assertEquals("CONNECT", classify(java.net.ConnectException("x"), false))
        assertEquals("IOException", classify(java.io.IOException("x"), true))
    }

    // --- compact capability line ----------------------------------------------------------------

    @Test fun compactCapsShowEachGateSeparately() {
        assertEquals(
            "role+ send+ op:ALLOWED rps+ rsms+ sim:1",
            capsCompact(caps()),
        )
        assertEquals(
            "role- send+ op:IGNORED rps- rsms- sim:?",
            capsCompact(caps(role = false, op = "IGNORED", subs = null, readSms = false)),
        )
        assertTrue(capsCompact(caps(subs = listOf(SubLite(1, 0, "A"), SubLite(2, 1, "B")))).endsWith("sim:1/2"))
    }
}
