package com.parda.app

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject

/**
 * Durable, encrypted-at-rest conversation history.
 *
 * ## Why this exists, and what it costs
 *
 * Until now the app held decrypted messages only in a Dart map and in
 * native [PlaintextHandle] buffers that were released whenever the app
 * left the foreground. That is a defensible posture for a demo and an
 * unusable one for a messenger: closing the app lost every conversation,
 * and simply scrolling a message off-screen after backgrounding rendered
 * it permanently as "Message no longer available".
 *
 * **The trade-off is real and is not hidden.** Sub-Phase 4.5C's position
 * was that decrypted plaintext should live only in a locked native
 * buffer and never be written down. A message stored here is written
 * down — encrypted under an Android Keystore master key, the same
 * boundary [PersistentSignalStore] already uses for identity material,
 * but on disk nonetheless. An adversary who compromises the Keystore and
 * images the device recovers conversation history; against the previous
 * arrangement they would have had to capture volatile memory while the
 * app was foregrounded.
 *
 * This is the same trade `parda-client-store` already makes in the Rust
 * workspace (SQLCipher-backed history), and the same one every practical
 * encrypted messenger makes. It is opt-out: see
 * [MessageStore.setEnabled]. With history disabled the app behaves as it
 * did before — messages live only for the current session.
 *
 * ## Storage shape
 *
 * One entry per message rather than one blob per conversation, so
 * appending a message never rewrites the whole history and a corrupted
 * entry costs one message rather than an entire thread.
 */
class MessageStore private constructor(private val prefs: SharedPreferences) {

    companion object {
        private const val PREFS_NAME = "parda_message_history"
        private const val PREFIX_MESSAGE = "m|"
        private const val KEY_ENABLED = "history_enabled"

        /**
         * Messages retained per conversation. Bounded so a long-lived
         * install cannot grow this store without limit; the oldest are
         * dropped first.
         */
        const val MAX_PER_CONVERSATION = 500

        fun open(context: Context): MessageStore {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            val prefs = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
            return MessageStore(prefs)
        }
    }

    /** History defaults to on; without it the app is not a messenger. */
    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, true)

    /**
     * Turn history on or off. Turning it **off deletes everything already
     * stored** — leaving it behind would make the setting a lie.
     */
    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).apply()
        if (!enabled) clearAll()
    }

    /**
     * Append one message. No-op when history is disabled, so callers do
     * not each have to check.
     *
     * `id` is the caller's own identifier and is used as the storage key,
     * which makes appending the same message twice idempotent — relevant
     * because the relay's fetch is destructive but a retried poll can
     * still re-present an id.
     */
    fun append(
        id: String,
        peer: String,
        senderId: String,
        body: String,
        timestampMs: Long,
        outgoing: Boolean,
    ) {
        if (!isEnabled()) return
        val json = JSONObject()
            .put("id", id)
            .put("peer", peer)
            .put("senderId", senderId)
            .put("body", body)
            .put("ts", timestampMs)
            .put("outgoing", outgoing)
        prefs.edit().putString(key(peer, id), json.toString()).apply()
        trim(peer)
    }

    /** All stored messages for `peer`, oldest first. */
    fun history(peer: String): List<JSONObject> {
        val prefix = "$PREFIX_MESSAGE$peer|"
        return prefs.all.entries
            .filter { it.key.startsWith(prefix) }
            .mapNotNull { entry ->
                val raw = entry.value as? String ?: return@mapNotNull null
                try {
                    JSONObject(raw)
                } catch (e: Exception) {
                    // One unreadable entry must not take the thread with
                    // it — drop it and keep going.
                    android.util.Log.w("MessageStore", "dropping unreadable entry ${entry.key}", e)
                    null
                }
            }
            .sortedBy { it.optLong("ts") }
    }

    /** Every peer with stored history, so the conversation list survives a restart. */
    fun conversations(): List<String> =
        prefs.all.keys
            .filter { it.startsWith(PREFIX_MESSAGE) }
            .mapNotNull { it.removePrefix(PREFIX_MESSAGE).substringBefore('|').ifEmpty { null } }
            .distinct()

    fun deleteConversation(peer: String) {
        val prefix = "$PREFIX_MESSAGE$peer|"
        val editor = prefs.edit()
        prefs.all.keys.filter { it.startsWith(prefix) }.forEach { editor.remove(it) }
        editor.apply()
    }

    fun clearAll() {
        val editor = prefs.edit()
        prefs.all.keys.filter { it.startsWith(PREFIX_MESSAGE) }.forEach { editor.remove(it) }
        editor.apply()
    }

    /** Drop the oldest entries once a conversation exceeds the cap. */
    private fun trim(peer: String) {
        val prefix = "$PREFIX_MESSAGE$peer|"
        val keys = prefs.all.entries
            .filter { it.key.startsWith(prefix) }
            .mapNotNull { entry ->
                val raw = entry.value as? String ?: return@mapNotNull null
                val ts = try {
                    JSONObject(raw).optLong("ts")
                } catch (e: Exception) {
                    0L
                }
                entry.key to ts
            }
        if (keys.size <= MAX_PER_CONVERSATION) return

        val editor = prefs.edit()
        keys.sortedBy { it.second }
            .take(keys.size - MAX_PER_CONVERSATION)
            .forEach { editor.remove(it.first) }
        editor.apply()
    }

    /** `peer` is escaped so a `|` in a user ID cannot forge a key boundary. */
    private fun key(peer: String, id: String): String =
        "$PREFIX_MESSAGE${peer.replace("|", "%7C")}|$id"
}
