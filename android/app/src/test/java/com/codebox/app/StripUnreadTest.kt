package com.codebox.app

import org.junit.Assert.assertEquals
import org.junit.Test

// The duplicate that shipped once: the broadcast path forwarded "这次没有验证码" while the
// notification path forwarded "[2 unread]这次没有验证码", so (sender, body) dedup saw two messages.
// stripUnreadPrefix must reduce the decorated form to the raw one — and leave real bodies alone.
class StripUnreadTest {
    @Test fun englishUnread() =
        assertEquals("这次没有验证码", stripUnreadPrefix("[2 unread]这次没有验证码"))

    @Test fun chineseUnread() =
        assertEquals("你的验证码是 123456", stripUnreadPrefix("[3条未读]你的验证码是 123456"))

    @Test fun englishNew() =
        assertEquals("code 9931", stripUnreadPrefix("[5 new] code 9931"))

    @Test fun bareCount() =
        assertEquals("hello", stripUnreadPrefix("[9] hello"))

    // No digit inside the bracket → a genuine bracketed body must survive untouched.
    @Test fun keepsNonCountBracket() =
        assertEquals("[验证码] 998877", stripUnreadPrefix("[验证码] 998877"))

    // A bracket mid-body is not a prefix and must not be stripped.
    @Test fun onlyStripsLeading() =
        assertEquals("会议 [2] 开始", stripUnreadPrefix("会议 [2] 开始"))

    // Undecorated body is a no-op.
    @Test fun plainUnchanged() =
        assertEquals("这次没有验证码", stripUnreadPrefix("这次没有验证码"))
}
