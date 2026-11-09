package top.mirv.fedup.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build

/**
 * Temporary narrow lab-only TUN service.
 *
 * The notification explicitly states that this does NOT protect the Internet.
 * The operator must enroll the phone and opt in to replacing the existing
 * Android VPN. Always-on / Lockdown remain disabled in AndroidManifest.xml.
 */
class FedUpVpnService : VpnService() {
    companion object {
        const val START = "top.mirv.fedup.android.START_LAB"
        const val STOP = "top.mirv.fedup.android.STOP_LAB"
        const val ENDPOINT = "fedup.endpoint"
        private const val NOTIFICATION_ID = 42
        private const val CHANNEL = "fedup-lab-session"
    }

    @Volatile private var session: LabTunnelSession? = null

    @Synchronized
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        if (intent?.action != START || session != null) {
            if (session == null) stopSelf(startId)
            return START_NOT_STICKY
        }
        if (prepare(this) != null ||
            EnrollmentManager(this).device()?.enrolled != true ||
            !NativePacketPolicy.available()) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val endpoint = intent.getStringExtra(ENDPOINT) ?: run {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        try {
            TlsProbe.Endpoint.parse(endpoint)
            showNotification(false)
        } catch (_: Exception) {
            stopSelf(startId)
            return START_NOT_STICKY
        }

        val newSession = LabTunnelSession(this, EnrollmentManager(this), endpoint) {
            showNotification(true)
        }
        session = newSession
        Thread({
            try {
                newSession.run()
            } catch (error: Exception) {
                // Never log certs, invitation tokens, private keys or packet data.
                android.util.Log.w("FedUpLab", "Lab tunnel stopped: " + error.javaClass.simpleName)
            } finally {
                newSession.stop()
                session = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }, "fedup-lab-tunnel").start()
        return START_NOT_STICKY
    }

    private fun showNotification(connected: Boolean) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "FedUp laboratory", NotificationManager.IMPORTANCE_LOW)
        )
        val stop = PendingIntent.getService(
            this, 17, Intent(this, FedUpVpnService::class.java).setAction(STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(if (connected) "FedUp LAB — тестовый IP-туннель"
                else "FedUp LAB — проверка соединения")
            .setContentText("Интернет и DNS НЕ защищены. Только тестовые IP.")
            .setOngoing(true)
            .addAction(Notification.Action.Builder(
                android.R.drawable.ic_menu_close_clear_cancel, "Отключить", stop
            ).build())
            .build()
        if (connected) {
            manager.notify(NOTIFICATION_ID, notification)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    @Synchronized
    private fun shutdown() {
        session?.stop()
        session = null
    }

    override fun onRevoke() {
        shutdown()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }
}
