package com.codebox.app

import android.app.Activity
import android.os.Bundle

// Stub compose screen required for default-SMS-app eligibility. This is a dedicated
// forwarding phone, so there is nothing to compose — just close immediately.
class ComposeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        finish()
    }
}
