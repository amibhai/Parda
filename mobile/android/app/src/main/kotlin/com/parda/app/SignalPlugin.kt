package com.parda.app

import android.content.Context
import android.util.Base64
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import org.signal.libsignal.protocol.*
import org.signal.libsignal.protocol.ecc.Curve
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.*

/**
 * PARDA Signal Protocol plugin for Android.
 *
 * Bridges Flutter MethodChannel calls to libsignal-android operations.
 * Session and identity state is held in [PersistentSignalStore], so it
 * survives process death — see that class for what its
 * "hardware-backed" storage does and does not mean.
 *
 * ## Method channel: `com.parda.app/signal`
 *
 * | Method | Returns |
 * |--------|---------|
 * | `isEnrolled` | `Boolean` |
 * | `localUserId` | `String?` |
 * | `generateIdentity(userId, registrationId)` | `Map` (prekey bundle JSON) |
 * | `getPreKeyBundle` | `Map` (a bundle built from currently-available prekeys) |
 * | `processPreKeyBundle(remoteUserId, bundle)` | `void` |
 * | `encryptMessage(remoteUserId, plaintext)` | `Map` (envelope JSON) |
 * | `decryptMessage(envelope)` | `Long` — a `PlaintextBridge` handle, never raw bytes (Sub-Phase 4.5C) |
 * | `hasSession(remoteUserId)` | `Boolean` |
 * | `knownPeers` | `List<String>` |
 * | `safetyNumber(remoteUserId)` | `Map` — 60-digit fingerprint (Sub-Phase 4.5D) |
 * | `burnConversation(remoteUserId)` | `void` |
 * | `wipeIdentity` | `void` |
 */
class SignalPlugin : FlutterPlugin, MethodCallHandler {

    private lateinit var channel: MethodChannel
    private lateinit var context: Context

    private var protocolStore: PersistentSignalStore? = null

    companion object {
        const val CHANNEL = "com.parda.app/signal"
        const val PREKEY_POOL_SIZE = 100

        /**
         * Domain-separation label for the mobile safety number. Must stay
         * byte-identical to `FINGERPRINT_CONTEXT` in
         * `protocol/src/trust.rs`, or a Rust peer and an Android peer
         * would compute different fingerprints for the same key pair and
         * users comparing them would see a spurious mismatch.
         */
        val FINGERPRINT_CONTEXT = "PARDA-Fingerprint-v1".toByteArray(Charsets.UTF_8)
        const val FINGERPRINT_LEN = 60
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
        // Reload any previously-enrolled identity up front, so the very
        // first Dart call already sees the real state rather than racing it.
        protocolStore = try {
            PersistentSignalStore.load(context)
        } catch (e: Exception) {
            android.util.Log.e(CHANNEL, "failed to load persisted identity", e)
            null
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "isEnrolled" -> result.success(protocolStore != null)
                "localUserId" -> result.success(protocolStore?.localUserId)
                "generateIdentity" -> handleGenerateIdentity(call, result)
                "getPreKeyBundle" -> handleGetPreKeyBundle(result)
                "processPreKeyBundle" -> handleProcessPreKeyBundle(call, result)
                "encryptMessage" -> handleEncryptMessage(call, result)
                "decryptMessage" -> handleDecryptMessage(call, result)
                "hasSession" -> handleHasSession(call, result)
                "knownPeers" -> result.success(protocolStore?.knownPeers() ?: emptyList<String>())
                "safetyNumber" -> handleSafetyNumber(call, result)
                "burnConversation" -> handleBurnConversation(call, result)
                "wipeIdentity" -> {
                    PersistentSignalStore.wipe(context)
                    protocolStore = null
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error("SIGNAL_ERROR", e.message, e.stackTraceToString())
        }
    }

    // ── generateIdentity ─────────────────────────────────────────────────────

    private fun handleGenerateIdentity(call: MethodCall, result: Result) {
        val userId = call.argument<String>("userId")
            ?: return result.error("BAD_ARGS", "userId is required", null)
        val registrationId = call.argument<Int>("registrationId") ?: 1

        val identityKeyPair = Curve.generateKeyPair()
        val identityKey = IdentityKey(identityKeyPair.publicKey)
        val fullIdentity = IdentityKeyPair(identityKey, identityKeyPair.privateKey)

        val store = PersistentSignalStore.create(context, fullIdentity, registrationId, userId)
        protocolStore = store

        // Signed prekey
        val signedPreKeyPair = Curve.generateKeyPair()
        val signedPreKeyId = 1
        val signedPreKeySig = Curve.calculateSignature(
            identityKeyPair.privateKey,
            signedPreKeyPair.publicKey.serialize()
        )
        val signedPreKey = SignedPreKeyRecord(
            signedPreKeyId,
            System.currentTimeMillis(),
            signedPreKeyPair,
            signedPreKeySig
        )
        store.storeSignedPreKey(signedPreKeyId, signedPreKey)

        // One-time prekeys. `KeyHelper.generatePreKeys(start, count)` — what
        // this was originally written against — does not exist in the current
        // libsignal-android API (confirmed by reading KeyHelper.java at the
        // tag this project's Rust dependency pins, v0.66.0: it has only
        // `generateRegistrationId`). Constructed here from primitives that do
        // exist.
        for (id in 1..PREKEY_POOL_SIZE) {
            store.storePreKey(id, PreKeyRecord(id, Curve.generateKeyPair()))
        }

        result.success(buildBundleMap(store))
    }

    // ── getPreKeyBundle ───────────────────────────────────────────────────────

    private fun handleGetPreKeyBundle(result: Result) {
        val store = requireStore(result) ?: return
        result.success(buildBundleMap(store))
    }

    /**
     * Build the prekey bundle this device publishes to the relay.
     *
     * Hands out the lowest-numbered *unused* one-time prekey. Previously
     * this returned a placeholder `{"registered": true}`, which the relay
     * would store and then serve to peers as a bundle with no usable key
     * material — so a second device could never establish a session at
     * all. Replenishment when the pool runs low is not implemented; when
     * it empties, `one_time_prekey_*` is omitted and X3DH proceeds
     * without a one-time prekey, which libsignal supports (with the
     * documented reduction in forward secrecy for that first message).
     */
    private fun buildBundleMap(store: PersistentSignalStore): Map<String, Any?> {
        // `IdentityKeyPair.publicKey` is already an `IdentityKey`, not a raw
        // `ECPublicKey` — no wrapping needed here (unlike at generation time,
        // where the key comes from `Curve.generateKeyPair()`).
        val identityKey: IdentityKey = store.identityKeyPair.publicKey
        val signedPreKey = store.loadSignedPreKey(1)
        val availablePreKeyId = store.availablePreKeyIds().firstOrNull()
        val oneTimePreKey = availablePreKeyId?.let { store.loadPreKey(it) }

        return mapOf(
            "registration_id" to store.registrationId,
            "device_id" to 1,
            "identity_key" to b64(identityKey.serialize()),
            "signed_prekey_id" to 1,
            "signed_prekey_public" to b64(signedPreKey.keyPair.publicKey.serialize()),
            "signed_prekey_signature" to b64(signedPreKey.signature),
            "one_time_prekey_id" to availablePreKeyId,
            "one_time_prekey_public" to oneTimePreKey?.keyPair?.publicKey?.serialize()?.let { b64(it) }
        )
    }

    // ── processPreKeyBundle ───────────────────────────────────────────────────

    private fun handleProcessPreKeyBundle(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        val bundleMap = call.argument<Map<String, Any>>("bundle")!!

        val remoteAddress = SignalProtocolAddress(remoteUserId, 1)
        val identityKey = IdentityKey(d64(bundleMap["identity_key"] as String), 0)
        val signedPreKeyId = (bundleMap["signed_prekey_id"] as Number).toInt()
        val signedPreKeyPub = Curve.decodePoint(d64(bundleMap["signed_prekey_public"] as String), 0)
        val signature = d64(bundleMap["signed_prekey_signature"] as String)

        val oneTimePreKeyId = (bundleMap["one_time_prekey_id"] as? Number)?.toInt()
        val oneTimePreKeyPub = (bundleMap["one_time_prekey_public"] as? String)
            ?.let { Curve.decodePoint(d64(it), 0) }

        val preKeyBundle = PreKeyBundle(
            (bundleMap["registration_id"] as Number).toInt(),
            1,
            oneTimePreKeyId ?: 0,
            oneTimePreKeyPub,
            signedPreKeyId,
            signedPreKeyPub,
            signature,
            identityKey
        )

        SessionBuilder(store, remoteAddress).process(preKeyBundle)
        result.success(null)
    }

    // ── encryptMessage ────────────────────────────────────────────────────────

    private fun handleEncryptMessage(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        val plaintext = call.argument<ByteArray>("plaintext")!!

        try {
            val remoteAddress = SignalProtocolAddress(remoteUserId, 1)
            val cipherMessage = SessionCipher(store, remoteAddress).encrypt(plaintext)

            val envelopeType = when (cipherMessage.type) {
                CiphertextMessage.PREKEY_TYPE -> "pre_key"
                else -> "ratchet"
            }

            val envelopeMap = mapOf(
                // Previously the literal string "local", which meant the
                // *recipient* looked up a session under the address "local"
                // instead of the real sender and could never decrypt. The
                // sender's own enrolled user ID is the only value that lets
                // the far side resolve the right session.
                "sender_id" to (store.localUserId ?: ""),
                "recipient_id" to remoteUserId,
                "ciphertext" to b64(cipherMessage.serialize()),
                "envelope_type" to envelopeType,
                "timestamp_ms" to System.currentTimeMillis(),
                // Explicit rather than relying on the relay's serde default:
                // this envelope carries Phase 2 fields, so it is a v2 envelope
                // and should say so on the wire.
                "version" to 2,
                "sealed_sender" to false
            )
            result.success(envelopeMap)
        } finally {
            // Sub-Phase 3C: `plaintext` is a plain JVM ByteArray handed across
            // the MethodChannel; nothing clears it once libsignal has consumed
            // it, so it would otherwise sit as an unmanaged copy subject only
            // to GC. `finally` so the exception path is covered too.
            java.util.Arrays.fill(plaintext, 0)
        }
    }

    // ── decryptMessage ────────────────────────────────────────────────────────

    private fun handleDecryptMessage(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val envelopeMap = call.argument<Map<String, Any>>("envelope")!!

        val senderId = envelopeMap["sender_id"] as String
        val envelopeType = envelopeMap["envelope_type"] as String
        val ciphertextBytes = d64(envelopeMap["ciphertext"] as String)

        val senderAddress = SignalProtocolAddress(senderId, 1)
        val sessionCipher = SessionCipher(store, senderAddress)

        val plaintext = when (envelopeType) {
            "pre_key" -> sessionCipher.decrypt(PreKeySignalMessage(ciphertextBytes))
            else -> sessionCipher.decrypt(SignalMessage(ciphertextBytes))
        }
        try {
            // Sub-Phase 4.5C: hand Dart an opaque native handle rather than
            // the decrypted bytes — see PlaintextBridge.kt and
            // docs/phase4.5c-dart-plaintext-design.md.
            val handle = PlaintextBridge.nativePlaintextNew(plaintext)
            if (handle == 0L) {
                result.error("PLAINTEXT_HANDLE_FAILED", "Failed to hand decrypted content to the native plaintext buffer", null)
            } else {
                result.success(handle)
            }
        } finally {
            java.util.Arrays.fill(plaintext, 0)
        }
    }

    // ── hasSession / knownPeers ───────────────────────────────────────────────

    private fun handleHasSession(call: MethodCall, result: Result) {
        val store = protocolStore ?: return result.success(false)
        val remoteUserId = call.argument<String>("remoteUserId")!!
        result.success(store.containsSession(SignalProtocolAddress(remoteUserId, 1)))
    }

    // ── safetyNumber (Sub-Phase 4.5D) ─────────────────────────────────────────

    /**
     * Compute the 60-digit safety number for a conversation.
     *
     * **Must stay byte-compatible with `protocol/src/trust.rs`'s
     * `Fingerprint::compute`** — same HKDF-SHA256 construction, same
     * `PARDA-Fingerprint-v1` label as both salt and info, same
     * sorted-serialized-keys input ordering, same 60-byte output chunked
     * into twelve big-endian 40-bit groups reduced mod 100000. A
     * divergence would show users a mismatch between two honest devices,
     * which is worse than having no fingerprint at all. As on the Rust
     * side, this is inspired by Signal's safety-number concept and is
     * explicitly *not* bit-compatible with Signal's own algorithm.
     */
    private fun handleSafetyNumber(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        val remote = store.getIdentity(SignalProtocolAddress(remoteUserId, 1))
            ?: return result.error(
                "NO_IDENTITY",
                "No identity key on file for $remoteUserId — start a conversation first",
                null
            )

        val local = store.identityKeyPair.publicKey.serialize()
        val digits = fingerprintDigits(local, remote.serialize())
        result.success(mapOf("digits" to digits, "peer" to remoteUserId))
    }

    private fun fingerprintDigits(localKey: ByteArray, remoteKey: ByteArray): String {
        // Lexicographic sort so both sides feed HKDF identical input.
        val first: ByteArray
        val second: ByteArray
        if (compareUnsigned(localKey, remoteKey) <= 0) {
            first = localKey; second = remoteKey
        } else {
            first = remoteKey; second = localKey
        }
        val ikm = first + second
        val okm = hkdfSha256(FINGERPRINT_CONTEXT, ikm, FINGERPRINT_CONTEXT, FINGERPRINT_LEN)

        return (0 until 12).joinToString(" ") { group ->
            var value = 0L
            for (i in 0 until 5) {
                value = (value shl 8) or (okm[group * 5 + i].toLong() and 0xFF)
            }
            "%05d".format(value % 100000)
        }
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    /** RFC 5869 HKDF-SHA256. Extract-then-expand, via the JDK's own HMAC. */
    private fun hkdfSha256(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        val out = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val n = minOf(previous.size, length - offset)
            System.arraycopy(previous, 0, out, offset, n)
            offset += n
            counter++
        }
        return out
    }

    // ── burnConversation ──────────────────────────────────────────────────────

    private fun handleBurnConversation(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        store.burnConversation(remoteUserId)
        result.success(null)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun requireStore(result: Result): PersistentSignalStore? {
        val store = protocolStore
        if (store == null) {
            result.error("NOT_ENROLLED", "Call generateIdentity first", null)
            return null
        }
        return store
    }

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun d64(s: String): ByteArray = Base64.decode(s, Base64.NO_WRAP)
}
