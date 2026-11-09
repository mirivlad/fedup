package top.mirv.fedup.android

import android.content.Intent
import android.net.VpnService

/**
 * Service declaration/lifecycle scaffold only. Intentionally fail closed:
 * there is no Android TLS transport, certificate enrollment, protected socket,
 * route/DNS policy or TUN forwarding loop yet.
 *
 * Android must never interpret this scaffold as a working VPN connection.
 */
class FedUpVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Do not call Builder.establish(): we cannot safely deliver packets.
        // Do not restart automatically as an inoperative system VPN.
        stopSelf(startId)
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        // No descriptor is opened in this laboratory version.
        stopSelf()
        super.onRevoke()
    }
}
