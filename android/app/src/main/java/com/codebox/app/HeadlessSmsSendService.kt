package com.codebox.app

import android.app.Service
import android.content.Intent
import android.os.IBinder

// Stub "respond via message" service required for default-SMS-app eligibility. No-op.
class HeadlessSmsSendService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        stopSelf(startId)
        return START_NOT_STICKY
    }
}
