package com.parda.app

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

/**
 * A [SignalProtocolStore] whose state survives process death.
 *
 * ## Why this exists
 *
 * `SignalPlugin` previously held an `InMemorySignalProtocolStore` and
 * nothing else. The Dart layer persisted the *user ID* in
 * `flutter_secure_storage` and treated its presence as "enrolled" — so
 * after any restart the app believed it was enrolled while holding no
 * identity key, no prekeys, and no sessions. Every send failed with
 * `NOT_ENROLLED` and there was no recovery path short of clearing app
 * data. This class closes that gap.
 *
 * ## Design: decorate, don't reimplement
 *
 * `InMemorySignalProtocolStore` remains the source of truth in memory;
 * this class wraps it and mirrors every mutation to disk, reloading on
 * construction. Reimplementing the four store traits by hand would mean
 * hand-rolling ratchet-state bookkeeping — exactly the class of thing
 * this project refuses to do for cryptographic code (see
 * `docs/phase3-3a-self-destruct-design.md` §1 for the same reasoning
 * applied to the self-destruct KDF). Every value written here is a blob
 * produced by libsignal's own `serialize()` and read back by its own
 * deserializing constructor; this class never parses key material
 * itself.
 *
 * ## What "hardware-backed" does and does not mean here
 *
 * Storage is [EncryptedSharedPreferences], whose master key lives in the
 * Android Keystore (hardware-backed / StrongBox where the device offers
 * it). **The Curve25519 identity private key itself is not held inside
 * the Keystore** — Android's Keystore does not expose the X25519/Ed25519
 * operations libsignal's Double Ratchet needs, so the key must be
 * available to userspace to be usable at all. What the Keystore protects
 * is the key that encrypts this store at rest. That is a real and
 * meaningful boundary (an attacker with the raw preferences file but not
 * the device's Keystore cannot read it) and a materially weaker one than
 * "the private key never leaves secure hardware." Stated here because
 * the README previously implied the stronger claim.
 */
class PersistentSignalStore private constructor(
    private val prefs: SharedPreferences,
    private val delegate: InMemorySignalProtocolStore,
) : SignalProtocolStore by delegate {

    companion object {
        private const val PREFS_NAME = "parda_signal_store"
        private const val KEY_IDENTITY = "identity_key_pair"
        private const val KEY_REGISTRATION_ID = "registration_id"
        private const val KEY_LOCAL_USER_ID = "local_user_id"
        private const val PREFIX_PREKEY = "prekey_"
        private const val PREFIX_SIGNED_PREKEY = "signed_prekey_"
        private const val PREFIX_SESSION = "session_"
        private const val PREFIX_TRUSTED_IDENTITY = "identity_"

        private fun openPrefs(context: Context): SharedPreferences {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            return EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
        }

        /** `true` if an identity has already been generated on this device. */
        fun isEnrolled(context: Context): Boolean =
            openPrefs(context).contains(KEY_IDENTITY)

        fun localUserId(context: Context): String? =
            openPrefs(context).getString(KEY_LOCAL_USER_ID, null)

        /**
         * Load the persisted identity and all associated state. Returns
         * `null` if this device has never enrolled — callers must treat
         * that as "generate a new identity", never as an error to retry.
         */
        fun load(context: Context): PersistentSignalStore? {
            val prefs = openPrefs(context)
            val identityB64 = prefs.getString(KEY_IDENTITY, null) ?: return null
            val registrationId = prefs.getInt(KEY_REGISTRATION_ID, 0)

            val identityKeyPair = IdentityKeyPair(decode(identityB64))
            val delegate = InMemorySignalProtocolStore(identityKeyPair, registrationId)
            val store = PersistentSignalStore(prefs, delegate)
            store.restoreInto(delegate)
            return store
        }

        /** Generate and persist a brand-new identity, replacing any existing one. */
        fun create(
            context: Context,
            identityKeyPair: IdentityKeyPair,
            registrationId: Int,
            localUserId: String,
        ): PersistentSignalStore {
            val prefs = openPrefs(context)
            prefs.edit().clear().apply()
            prefs.edit()
                .putString(KEY_IDENTITY, encode(identityKeyPair.serialize()))
                .putInt(KEY_REGISTRATION_ID, registrationId)
                .putString(KEY_LOCAL_USER_ID, localUserId)
                .apply()
            val delegate = InMemorySignalProtocolStore(identityKeyPair, registrationId)
            return PersistentSignalStore(prefs, delegate)
        }

        /** Erase every trace of this device's identity. */
        fun wipe(context: Context) {
            openPrefs(context).edit().clear().apply()
        }

        private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
        private fun decode(s: String): ByteArray = Base64.decode(s, Base64.NO_WRAP)
    }

    val localUserId: String? get() = prefs.getString(KEY_LOCAL_USER_ID, null)

    val registrationId: Int get() = prefs.getInt(KEY_REGISTRATION_ID, 0)

    /**
     * Rehydrate every persisted record into `target`.
     *
     * A record that fails to deserialize is skipped rather than being
     * allowed to abort startup: losing one session means that
     * conversation needs re-establishing, whereas throwing here would
     * make the whole app unusable and unrecoverable without clearing app
     * data. The failure is logged, not silent.
     */
    private fun restoreInto(target: InMemorySignalProtocolStore) {
        for ((key, value) in prefs.all) {
            val blob = value as? String ?: continue
            try {
                when {
                    key.startsWith(PREFIX_PREKEY) -> {
                        val id = key.removePrefix(PREFIX_PREKEY).toInt()
                        target.storePreKey(id, PreKeyRecord(decode(blob)))
                    }
                    key.startsWith(PREFIX_SIGNED_PREKEY) -> {
                        val id = key.removePrefix(PREFIX_SIGNED_PREKEY).toInt()
                        target.storeSignedPreKey(id, SignedPreKeyRecord(decode(blob)))
                    }
                    key.startsWith(PREFIX_SESSION) -> {
                        val address = parseAddress(key.removePrefix(PREFIX_SESSION)) ?: continue
                        target.storeSession(address, SessionRecord(decode(blob)))
                    }
                    key.startsWith(PREFIX_TRUSTED_IDENTITY) -> {
                        val address = parseAddress(key.removePrefix(PREFIX_TRUSTED_IDENTITY)) ?: continue
                        target.saveIdentity(address, IdentityKey(decode(blob), 0))
                    }
                }
            } catch (e: Exception) {
                android.util.Log.w(
                    "PersistentSignalStore",
                    "dropping unreadable record $key — the affected conversation will need " +
                        "re-establishing, but the app stays usable",
                    e,
                )
            }
        }
    }

    /** `name::deviceId` — `name` may itself contain no `::` sequence. */
    private fun parseAddress(encoded: String): SignalProtocolAddress? {
        val idx = encoded.lastIndexOf("::")
        if (idx < 0) return null
        val name = encoded.substring(0, idx)
        val deviceId = encoded.substring(idx + 2).toIntOrNull() ?: return null
        return SignalProtocolAddress(name, deviceId)
    }

    private fun addressKey(prefix: String, address: SignalProtocolAddress): String =
        "$prefix${address.name}::${address.deviceId}"

    // ── Mirrored mutations ──────────────────────────────────────────────
    //
    // Each override delegates first (so in-memory behaviour is byte-for-byte
    // what libsignal's own store does) and then mirrors the resulting record
    // to disk. Read paths are inherited unchanged via `by delegate`.

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        delegate.storePreKey(preKeyId, record)
        prefs.edit().putString("$PREFIX_PREKEY$preKeyId", encode(record.serialize())).apply()
    }

    override fun removePreKey(preKeyId: Int) {
        delegate.removePreKey(preKeyId)
        // One-time prekeys are single-use by design; dropping the row is the
        // whole point, so this is a delete rather than a tombstone.
        prefs.edit().remove("$PREFIX_PREKEY$preKeyId").apply()
    }

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        delegate.storeSignedPreKey(signedPreKeyId, record)
        prefs.edit()
            .putString("$PREFIX_SIGNED_PREKEY$signedPreKeyId", encode(record.serialize()))
            .apply()
    }

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        delegate.removeSignedPreKey(signedPreKeyId)
        prefs.edit().remove("$PREFIX_SIGNED_PREKEY$signedPreKeyId").apply()
    }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        delegate.storeSession(address, record)
        prefs.edit()
            .putString(addressKey(PREFIX_SESSION, address), encode(record.serialize()))
            .apply()
    }

    override fun deleteSession(address: SignalProtocolAddress) {
        delegate.deleteSession(address)
        prefs.edit().remove(addressKey(PREFIX_SESSION, address)).apply()
    }

    override fun deleteAllSessions(name: String) {
        delegate.deleteAllSessions(name)
        val editor = prefs.edit()
        prefs.all.keys
            .filter { it.startsWith("$PREFIX_SESSION$name::") }
            .forEach { editor.remove(it) }
        editor.apply()
    }

    override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): Boolean {
        val changed = delegate.saveIdentity(address, identityKey)
        prefs.edit()
            .putString(addressKey(PREFIX_TRUSTED_IDENTITY, address), encode(identityKey.serialize()))
            .apply()
        return changed
    }

    /**
     * Remove all state for one conversation — the mobile counterpart of
     * `SessionManager::burn_conversation` (Sub-Phase 3D).
     *
     * Carries the same documented limitation as the Rust side: this
     * removes PARDA's own records, but `libsignal-protocol`'s
     * `PrivateKey` is a non-zeroizing `Copy` type, so libsignal's
     * internals may retain copies no code here can reach. The
     * conversation becomes unusable, which is real and testable; that is
     * a narrower claim than byte-level erasure. See
     * `docs/phase3-3a-self-destruct-design.md` §12.
     */
    fun burnConversation(name: String) {
        deleteAllSessions(name)
        val editor = prefs.edit()
        prefs.all.keys
            .filter { it.startsWith("$PREFIX_TRUSTED_IDENTITY$name::") }
            .forEach { editor.remove(it) }
        editor.apply()
    }

    /** Every peer this device currently holds a session with. */
    fun knownPeers(): List<String> =
        prefs.all.keys
            .filter { it.startsWith(PREFIX_SESSION) }
            .mapNotNull { parseAddress(it.removePrefix(PREFIX_SESSION))?.name }
            .distinct()
            .sorted()

    /** The identity public key, for fingerprint display (Sub-Phase 4.5D). */
    fun identityPublicKey(): ByteArray = delegate.identityKeyPair.publicKey.serialize()

    /** Unused prekey IDs still available to hand out in a bundle. */
    fun availablePreKeyIds(): List<Int> =
        prefs.all.keys
            .filter { it.startsWith(PREFIX_PREKEY) }
            .mapNotNull { it.removePrefix(PREFIX_PREKEY).toIntOrNull() }
            .sorted()
}
