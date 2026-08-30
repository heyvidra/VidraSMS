package com.codebox.app

import org.junit.Assert.assertEquals
import org.junit.Test

class CallerOfTest {
    @Test fun aospPutsCallerInText() =
        assertEquals("13812345678", callerOf("未接来电", "13812345678"))

    @Test fun oemDialerPutsCallerInTitle() =
        assertEquals("13812345678", callerOf("13812345678", "未接来电"))

    // The number test must win over the label test, so a non-Chinese/English label still works.
    @Test fun formattedNumberSurvivesForeignLabel() =
        assertEquals("1 380-013-8000", callerOf("Anruf in Abwesenheit", "1 380-013-8000"))

    // BidiFormatter wraps the value; the invisible marks must not end up in the message.
    @Test fun bidiMarksAreStripped() =
        assertEquals("+8613800138000", callerOf("Missed call", "‎+8613800138000‎"))

    // A caller in Contacts yields a name, not a number — fall back to "not the label".
    @Test fun contactNameFallsBackToLabelHeuristic() =
        assertEquals("张三", callerOf("未接来电", "张三"))

    @Test fun bothLabelsMeansUnknown() =
        assertEquals("未知号码", callerOf("未接来电", "Missed call"))
}
