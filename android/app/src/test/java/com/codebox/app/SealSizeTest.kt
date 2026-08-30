package com.codebox.app

import org.junit.Assert.assertTrue
import org.junit.Test

// The sealed payload has to stay under what the server accepts. Escaping is what used to blow
// past it: the body was clamped BEFORE escaping, and quotes/newlines double while control
// characters sextuple, so a maximal body could ship well over the limit and be rejected 4xx —
// which outcomeFor treats as permanent, dropping the message instead of retrying it.
class SealSizeTest {
    private val key = "00".repeat(32)

    private fun check(name: String, body: String, sender: String = "10086") {
        val sealed = sealMessage(key, sender, body, "SIM 1 \u00b7 \u4e2d\u56fd\u7535\u4fe1", "a1b2c3d4e5f60718")
        val size = sealed.toByteArray(Charsets.US_ASCII).size
        assertTrue("$name: sealed payload $size bytes exceeds $NTFY_MAX_BYTES", size <= NTFY_MAX_BYTES)
    }

    @Test fun plainLongBody() = check("plain", "\u9a8c\u8bc1\u7801 1234\u3002".repeat(500))
    @Test fun allQuotes() = check("quotes", "\"".repeat(4000))
    @Test fun allBackslashes() = check("backslashes", "\\\\".repeat(4000))
    @Test fun allNewlines() = check("newlines", "\n".repeat(4000))
    @Test fun allControlChars() = check("control", "\u0001".repeat(4000))
    @Test fun longSenderAndBody() = check("long sender", "x".repeat(4000), sender = "\"".repeat(200))
}
