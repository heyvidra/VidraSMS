package com.codebox.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

// Without this a phone that reboots (or updates the app) overnight silently stops forwarding
// until someone opens the app. BOOT_COMPLETED is exempt from the background-FGS-start ban, and
// specialUse is one of the types still allowed to be started from it on Android 14.
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> {
                ForwardService.start(context)
                KeepAliveWorker.schedule(context)
            }
        }
    }
}
