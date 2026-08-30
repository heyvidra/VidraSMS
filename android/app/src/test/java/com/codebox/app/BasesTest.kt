package com.codebox.app

import org.junit.Assert.assertEquals
import org.junit.Test

class BasesTest {
    @Test fun splitsTrimsAndKeepsOnlyHttps() {
        // trailing slash stripped, http:// and junk dropped, order preserved
        assertEquals(
            listOf("https://a.xyz", "https://b.xyz"),
            parseBases("https://a.xyz/, https://b.xyz , http://insecure.xyz, junk"),
        )
    }

    @Test fun singleDomainIsAOneElementList() {
        assertEquals(listOf("https://only.xyz"), parseBases("https://only.xyz"))
    }

    @Test fun blankIsEmpty() {
        assertEquals(emptyList<String>(), parseBases("   "))
    }
}
