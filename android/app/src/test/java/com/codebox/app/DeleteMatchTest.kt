package com.codebox.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// The sync-delete has to find the SAME message the stock app may have stored in its own format.
class DeleteMatchTest {
    @Test fun identicalStringsMatch() {
        assertTrue(sameAddress("13800138000", "13800138000"))
        assertTrue(sameAddress("淘宝", "淘宝"))
    }

    @Test fun countryCodeAndFormattingAreIgnored() {
        assertTrue(sameAddress("+8613800138000", "13800138000"))
        assertTrue(sameAddress("+86 138 0013 8000", "13800138000"))
        assertTrue(sameAddress("138-0013-8000", "+8613800138000"))
    }

    @Test fun differentNumbersDoNotMatch() {
        assertFalse(sameAddress("13800138000", "13800138001"))
        assertFalse(sameAddress("10086", "10010"))
    }

    @Test fun differentBrandNamesDoNotMatch() {
        // Both normalise to "" digits — must not be treated as equal.
        assertFalse(sameAddress("淘宝", "京东"))
        assertFalse(sameAddress("淘宝", ""))
    }

    @Test fun likeEscapeNeutralisesWildcards() {
        assertEquals("100\\%", likeEscape("100%"))
        assertEquals("a\\_b", likeEscape("a_b"))
        assertEquals("c:\\\\x", likeEscape("c:\\x"))
        assertEquals("plain", likeEscape("plain"))
    }
}
