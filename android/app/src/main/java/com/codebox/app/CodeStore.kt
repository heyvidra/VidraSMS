package com.codebox.app

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

data class Msg(val id: Long, val ts: Long, val sender: String, val body: String)

private class DbHelper(ctx: Context) : SQLiteOpenHelper(ctx, "codes.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        // ts = when the SMS arrived (for display); added = wall-clock of the insert (for dedup).
        db.execSQL(
            "CREATE TABLE msg (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, added INTEGER, sender TEXT, body TEXT)"
        )
    }
    override fun onUpgrade(db: SQLiteDatabase, old: Int, new: Int) {}
}

// The captured messages, on-device. Replaces reading content://sms, which needs the
// hard-restricted READ_SMS permission that a sideloaded install cannot be granted.
object CodeStore {
    // Two different dedup questions. (a) The SAME message seen twice: SMS_DELIVER and the
    // follow-on SMS_RECEIVED carry an identical PDU timestamp, so matching on ts is exact and
    // needs no time window — which matters because the window used to be the only guard and a
    // slow upload could push the second broadcast past it, forwarding the message twice.
    // (b) The same message seen by the two DIFFERENT capture paths, whose timestamps disagree
    // (broadcast PDU time vs notification post time); only a short window can catch that.
    private const val DEDUP_MS = 15_000L
    private const val CAP = 200

    @Volatile private var helper: DbHelper? = null
    private fun db(ctx: Context): SQLiteDatabase {
        helper ?: synchronized(this) { helper ?: DbHelper(ctx.applicationContext).also { helper = it } }
        return helper!!.writableDatabase
    }

    // Inserts and returns true, or returns false when an identical message was stored within the
    // last DEDUP_MS — which is how the two capture paths (and notification re-posts) collapse to
    // one entry. Synchronized so a concurrent add from both paths can't slip past the check.
    @Synchronized
    fun add(ctx: Context, sender: String, body: String, ts: Long): Boolean {
        val d = db(ctx)
        val cutoff = System.currentTimeMillis() - DEDUP_MS
        val stamp = if (ts > 0) ts else 0L
        d.rawQuery(
            "SELECT id FROM msg WHERE sender=? AND body=? AND ((?>0 AND ts=?) OR added>=?) LIMIT 1",
            arrayOf(sender, body, stamp.toString(), stamp.toString(), cutoff.toString())
        ).use { if (it.moveToFirst()) return false }

        d.insert("msg", null, ContentValues().apply {
            put("ts", if (ts > 0) ts else System.currentTimeMillis())
            put("added", System.currentTimeMillis())
            put("sender", sender)
            put("body", body)
        })
        // Keep the table bounded; the on-device list only ever shows the newest anyway.
        d.execSQL("DELETE FROM msg WHERE id NOT IN (SELECT id FROM msg ORDER BY id DESC LIMIT $CAP)")
        return true
    }

    // Mirror of a web-side delete: drop our own copy so the in-app list stops showing it. Exact
    // body, or a stored body that STARTS with it — the forwarded copy may have been clamped.
    fun remove(ctx: Context, sender: String, body: String): Int =
        db(ctx).delete(
            "msg", "sender=? AND (body=? OR body LIKE ? ESCAPE '\\')",
            arrayOf(sender, body, likeEscape(body) + "%"),
        )

    fun recent(ctx: Context): List<Msg> {
        val out = ArrayList<Msg>()
        db(ctx).rawQuery("SELECT id, ts, sender, body FROM msg ORDER BY id DESC LIMIT $CAP", null).use { c ->
            while (c.moveToNext()) out.add(Msg(c.getLong(0), c.getLong(1), c.getString(2), c.getString(3)))
        }
        return out
    }
}
