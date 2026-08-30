package com.codebox.app

import org.junit.Assert.assertEquals
import org.junit.Test

class OutcomeTest {
    @Test fun mapsStatusCodesToRetryPolicy() {
        assertEquals(Outcome.SUCCESS, outcomeFor(200))
        assertEquals(Outcome.RETRY, outcomeFor(429))   // rate limited -> back off and retry
        assertEquals(Outcome.RETRY, outcomeFor(503))   // server hiccup -> retry
        assertEquals(Outcome.FAILURE, outcomeFor(401)) // bad token -> retrying won't help
        assertEquals(Outcome.RETRY, outcomeFor(-1))    // HttpURLConnection error -> retry
    }

    // The exact forms below were verified against a live ntfy 2.27 container:
    // both plain ASCII and the RFC 2047 word came back with the title intact.
    @Test fun encodesTitlesSafelyForHeaders() {
        assertEquals("10086", encodeTitle("10086"))            // ASCII passes through
        assertEquals("SMS", encodeTitle("   "))                // blank -> fallback
        assertEquals("=?UTF-8?B?5Lit5Zu96ZO26KGM?=", encodeTitle("中国银行")) // CJK preserved
    }

    // ntfy 2.27 measured: 4095 bytes accepted, 4096 rejected with 400.
    @Test fun clampsBodiesToWhatNtfyAccepts() {
        val short = "【银行】验证码 823914"
        assertEquals(short, clampBody(short))                       // untouched when it fits

        val long = "验证码".repeat(510)                              // 4590 bytes
        val clamped = clampBody(long)
        assertEquals(true, clamped.toByteArray(Charsets.UTF_8).size <= NTFY_MAX_BYTES)
        assertEquals(true, clamped.endsWith("…[截断]"))
        assertEquals(false, clamped.contains('�'))             // no split-character junk
        assertEquals(true, clamped.startsWith("验证码验证码"))        // head (the OTP) survives
    }

    @Test fun clampNeverSplitsACharacter() {
        // Force a cut in the middle of a multi-byte char at every offset around the boundary.
        (1..8).forEach { n ->
            val out = clampBody("好".repeat(100), limit = 20 + n)
            assertEquals("U+FFFD leaked at limit ${20 + n}", false, out.contains('�'))
        }
    }

    @Test fun notesOriginalTimeOnlyWhenDelayed() {
        val now = 1_700_000_000_000L
        assertEquals("码", formatBody("码", now - 30_000, now))   // fresh -> untouched
        assertEquals("码", formatBody("码", 0L, now))              // no timestamp -> untouched
        assertEquals(true, formatBody("码", now - 3_600_000, now).startsWith("[原时间 "))
        assertEquals(true, formatBody("码", now - 3_600_000, now).endsWith("\n码"))
    }

    private val KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

    @Test fun sealedPayloadIsAsciiAndFitsTheServerLimit() {
        // The worst case: a maximum-length SMS from a long non-ASCII sender.
        val sealed = sealMessage(KEY, "中国工商银行客服中心", "验证码".repeat(2000))
        assertEquals(true, sealed.startsWith("v1:"))
        assertEquals("payload must be ASCII", true, sealed.all { it.code in 32..126 })
        assertEquals(
            "sealed payload exceeded the server limit: ${sealed.length}",
            true,
            sealed.toByteArray(Charsets.UTF_8).size <= NTFY_MAX_BYTES
        )
    }

    @Test fun sealedPayloadDiffersEachTimeForTheSameInput() {
        // A fixed IV would let anyone holding the ciphertexts spot repeated messages.
        val a = sealMessage(KEY, "10086", "验证码 1234")
        val b = sealMessage(KEY, "10086", "验证码 1234")
        assertEquals(false, a == b)
    }

    @Test fun jsonEscapingSurvivesHostileSmsText() {
        // A quote or backslash in an SMS would otherwise produce JSON the browser cannot parse.
        val nasty = "he said \"hi\"\\ then\nnewline\ttab"
        assertEquals(
            "\\\"", jsonEscape("\"")
        )
        assertEquals("\\\\", jsonEscape("\\"))
        assertEquals("\\n", jsonEscape("\n"))
        assertEquals(true, jsonEscape(nasty).none { it == '\n' || it == '\t' })
    }

    @Test fun hexKeyDecodesToThirtyTwoBytes() {
        assertEquals(32, hexToBytes(KEY).size)
        assertEquals(0x00.toByte(), hexToBytes(KEY)[0])
        assertEquals(0xff.toByte(), hexToBytes(KEY)[31])
    }

    @Test fun extractsTheCodeNextToTheKeyword() {
        assertEquals("520131", extractCode("【测试银行】您的验证码是 520131，5分钟内有效。"))
        assertEquals("4821", extractCode("您正在办理登录，动态密码 4821，切勿转发他人。"))
        assertEquals("837291", extractCode("Your verification code is 837291"))
        // The trap: an account number appears BEFORE the real code.
        assertEquals("5678", extractCode("尾号1234账户登录，验证码5678，请勿泄露。"))
    }

    @Test fun ignoresTransactionAndOtherSmsWithNoKeyword() {
        // Transaction SMS carries an account tail and an amount but no code keyword.
        assertEquals(null, extractCode("尾号1234账户于19:20支出500.00元，余额12345.67元。"))
        assertEquals(null, extractCode("订单20260827001已发货，物流单号SF1234567890。"))
        assertEquals(null, extractCode("会议室在3楼302"))
    }

    @Test fun handlesKeywordButNoUsableRun() {
        // Keyword present, but the only number is an amount → nothing to show.
        assertEquals(null, extractCode("验证码支付确认：消费2000.50元"))
        assertEquals("8899", extractCode("临时通行码 8899"))   // 通行码 is a keyword
    }

    @Test fun encodedTitleIsAlwaysAsciiSafe() {
        // HttpURLConnection would mangle any byte above 0x7E, so nothing may exceed it.
        listOf("中国银行", "10086", "Ünïcodé", "😀", "  张三  ").forEach { sender ->
            assertEquals(
                "non-ascii leaked for '$sender'",
                true,
                encodeTitle(sender).all { it.code in 32..126 }
            )
        }
    }
}
