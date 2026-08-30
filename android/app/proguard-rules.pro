# WorkManager loads the worker by class name; keep it so R8 can't rename/remove it and
# leave the DB pointing at a class that no longer exists.
-keep class com.codebox.app.SyncWorker { *; }
-keep class com.codebox.app.IncomingReceiver { *; }
-keep class com.codebox.app.CodeListener { *; }
