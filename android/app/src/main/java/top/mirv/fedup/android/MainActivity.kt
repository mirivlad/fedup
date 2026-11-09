package top.mirv.fedup.android

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Diagnostic screen. Deliberately offers no "connect" control and does not
 * request Android VPN consent until there is an authenticated transport.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(32, 48, 32, 32)
        }

        val title = TextView(this).apply {
            text = "FedUp — Android laboratory"
            textSize = 22f
        }
        val warning = TextView(this).apply {
            text = "VPN is not available yet. This build cannot connect, protect traffic, " +
                "or replace your existing VPN. Always-on and Lockdown are not enabled."
            textSize = 16f
            setPadding(0, 24, 0, 16)
        }
        val state = TextView(this).apply {
            text = "Native packet policy has not been tested on this device."
            textSize = 15f
        }
        val diagnostics = Button(this).apply {
            text = "Check Rust packet policy"
            setOnClickListener {
                val ready = NativePacketPolicy.available()
                state.text = if (ready) {
                    "Native Rust policy loaded (lab only). VPN transport is still unavailable."
                } else {
                    "Native Rust policy unavailable. Fail closed; no VPN interface created."
                }
            }
        }

        layout.addView(title, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        layout.addView(warning, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        layout.addView(diagnostics, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        layout.addView(state, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        setContentView(layout)
    }
}
