package com.codebox.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

// Stub. Exists only so the app qualifies as the default SMS app; MMS isn't handled.
class MmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) { /* no-op */ }
}
