package com.codebox.app

import org.junit.Assert.assertEquals
import org.junit.Test

// The bug that made a real OTP read as "最近没有验证码": a code ending a sentence ("...998877.")
// was rejected by the old (?![\d.]) guard, so the code filter dropped the whole message.
class ExtractCodeTest {
    @Test fun codeEndingWithPeriod() =
        assertEquals("998877", extractCode("HSBC: your verification code is 998877."))

    @Test fun codeEndingWithChinesePeriod() =
        assertEquals("5678", extractCode("【银行】您的验证码是5678。"))

    @Test fun plainCode() =
        assertEquals("123456", extractCode("验证码123456"))

    // Nearest digit run to the keyword wins, so an account tail before it is not mistaken.
    @Test fun nearestToKeywordWins() =
        assertEquals("5678", extractCode("尾号1234，验证码5678"))

    // A decimal amount must NOT be read as a code, even with a keyword present.
    @Test fun decimalIsNotACode() =
        assertEquals(null, extractCode("验证码支付 5000.00 元"))

    // No keyword → not a code (a bare number should not be copied as one).
    @Test fun noKeywordNoCode() =
        assertEquals(null, extractCode("您尾号1234支出500元"))
}
