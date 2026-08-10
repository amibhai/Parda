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
    private var messageStore: MessageStore? = null

    companion object {
        const val CHANNEL = "com.parda.app/signal"
        const val PREKEY_POOL_SIZE = 100

        /// Refill once fewer than this many one-time prekeys remain.
        const val PREKEY_LOW_WATER_MARK = 20

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
        messageStore = try {
            MessageStore.open(context)
        } catch (e: Exception) {
            // History is a convenience, not a correctness requirement —
            // losing it must not stop the app from starting.
            android.util.Log.e(CHANNEL, "failed to open message history", e)
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
                "knownPeers" -> handleKnownPeers(result)
                "safetyNumber" -> handleSafetyNumber(call, result)
                "burnConversation" -> handleBurnConversation(call, result)
                // ── Physical (QR) key exchange ──────────────────────
                "contactCard" -> handleContactCard(result)
                "importContact" -> handleImportContact(call, result)
                "isVerified" -> result.success(
                    protocolStore?.isVerified(call.argument<String>("remoteUserId")!!) ?: false
                )
                "markVerified" -> handleMarkVerified(call, result)
                "forgetVerification" -> {
                    protocolStore?.forgetVerification(call.argument<String>("remoteUserId")!!)
                    result.success(null)
                }
                // ── Encrypted local history ─────────────────────────
                "historyEnabled" -> result.success(messageStore?.isEnabled() ?: false)
                "setHistoryEnabled" -> {
                    messageStore?.setEnabled(call.argument<Boolean>("enabled") ?: true)
                    result.success(null)
                }
                "loadHistory" -> handleLoadHistory(call, result)
                "appendHistory" -> handleAppendHistory(call, result)
                "conversations" -> result.success(messageStore?.conversations() ?: emptyList<String>())
                "wipeIdentity" -> {
                    PersistentSignalStore.wipe(context)
                    // History outlives the identity otherwise, leaving
                    // readable plaintext behind after the user asked for
                    // everything to be erased.
                    messageStore?.clearAll()
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
        replenishPreKeysIfLow(store)
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

    /**
     * Top the one-time prekey pool back up when it runs low.
     *
     * Each incoming PreKey message consumes one, and nothing replaced
     * them: after 100 new sessions the pool emptied permanently and every
     * subsequent bundle went out without a one-time prekey. X3DH still
     * completes in that case, but with the reduced forward secrecy
     * libsignal documents for the first message — a silent, permanent
     * downgrade that would never have announced itself.
     *
     * New IDs continue past the highest ever issued rather than refilling
     * from 1, so a replenished key can never collide with one a peer is
     * still holding from an older bundle.
     */
    private fun replenishPreKeysIfLow(store: PersistentSignalStore) {
        val available = store.availablePreKeyIds()
        if (available.size >= PREKEY_LOW_WATER_MARK) return

        val nextId = (available.maxOrNull() ?: 0) + 1
        for (id in nextId until nextId + PREKEY_POOL_SIZE) {
            store.storePreKey(id, PreKeyRecord(id, Curve.generateKeyPair()))
        }
        android.util.Log.i(CHANNEL, "replenished one-time prekeys from id $nextId")
    }

    // ── processPreKeyBundle ───────────────────────────────────────────────────

    private fun handleProcessPreKeyBundle(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        val bundleMap = call.argument<Map<String, Any>>("bundle")!!

        val remoteAddress = SignalProtocolAddress(remoteUserId, 1)
        val identityKey = IdentityKey(d64(bundleMap["identity_key"] as String), 0)

        // Sub-Phase 4.5D, enforced. A bundle fetched from the relay is
        // whatever the relay chose to hand over; if the user has met this
        // peer and confirmed their key, a bundle carrying a *different*
        // key is refused outright rather than re-pinned. Without this
        // check the verification recorded by a QR scan would be
        // decorative — the relay could still substitute a key at the next
        // session rebuild.
        if (!store.identityMatchesVerified(remoteUserId, identityKey)) {
            return result.error(
                "IDENTITY_CHANGED",
                "The relay offered a different identity key for \"$remoteUserId\" than the one " +
                    "you verified in person. Refusing to start a session.",
                null
            )
        }

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

    // ── Physical key exchange (QR contact cards) ──────────────────────────────

    /**
     * This device's contact card: everything a peer needs to open a
     * session, with no relay involved.
     *
     * ## Why this matters more than convenience
     *
     * Fetching a bundle from `/v1/keys/{id}` is trust-on-first-use — the
     * relay hands over whatever key it holds, and a malicious or
     * compromised relay can substitute its own. That is exactly the
     * first-contact MITM `docs/phase4.5d-trust-bootstrapping-design.md`
     * §4 documents as undefended, and no amount of comparing safety
     * numbers *afterwards* helps if nobody compares them.
     *
     * A card scanned off another person's screen never passes through
     * the relay, so the relay is removed from the key-exchange path
     * entirely. [importContact] therefore records the scanned identity
     * as **verified**, and a later key change for that peer becomes a
     * hard failure rather than a silent re-pin.
     */
    private fun handleContactCard(result: Result) {
        val store = requireStore(result) ?: return
        val bundle = buildBundleMap(store).toMutableMap()
        bundle["v"] = 1
        bundle["user_id"] = store.localUserId
        result.success(bundle)
    }

    /**
     * Establish a session from a scanned contact card and mark the peer
     * verified.
     *
     * Refuses when the card's identity key contradicts one already
     * verified for that user ID: that is either an attack or the peer
     * genuinely reinstalling, and the two are indistinguishable from
     * here — so it fails loud and lets the user decide, rather than
     * silently replacing a key they once confirmed in person.
     */
    private fun handleImportContact(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val card = call.argument<Map<String, Any>>("card")
            ?: return result.error("BAD_ARGS", "card is required", null)

        val userId = card["user_id"] as? String
            ?: return result.error("BAD_CARD", "contact card has no user_id", null)
        if (userId == store.localUserId) {
            return result.error("SELF_CARD", "that is this device's own contact card", null)
        }

        val identityKey = IdentityKey(d64(card["identity_key"] as String), 0)

        if (!store.identityMatchesVerified(userId, identityKey)) {
            return result.error(
                "IDENTITY_CHANGED",
                "The key on this card does not match the one you previously verified for " +
                    "\"$userId\". If they reinstalled, remove the old verification first; " +
                    "otherwise treat this as an impersonation attempt.",
                null
            )
        }

        val address = SignalProtocolAddress(userId, 1)
        val signedPreKeyId = (card["signed_prekey_id"] as Number).toInt()
        val signedPreKeyPub = Curve.decodePoint(d64(card["signed_prekey_public"] as String), 0)
        val signature = d64(card["signed_prekey_signature"] as String)
        val oneTimePreKeyId = (card["one_time_prekey_id"] as? Number)?.toInt()
        val oneTimePreKeyPub = (card["one_time_prekey_public"] as? String)
            ?.let { Curve.decodePoint(d64(it), 0) }

        val preKeyBundle = PreKeyBundle(
            (card["registration_id"] as Number).toInt(),
            1,
            oneTimePreKeyId ?: 0,
            oneTimePreKeyPub,
            signedPreKeyId,
            signedPreKeyPub,
            signature,
            identityKey
        )

        // `SessionBuilder.process` verifies the signed prekey's signature
        // against the identity key on the card, so a card whose parts do
        // not belong together is rejected here rather than producing a
        // session that fails later in a confusing way.
        SessionBuilder(store, address).process(preKeyBundle)
        store.recordVerified(userId, identityKey)

        result.success(mapOf("user_id" to userId))
    }

    /**
     * Record the peer's *current* identity key as verified, after the
     * user compared safety numbers by hand.
     *
     * Reads the key from the session store rather than taking one as an
     * argument: the number the user just compared was computed from that
     * key, so anything else would confirm something they never saw.
     */
    private fun handleMarkVerified(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        val identity = store.getIdentity(SignalProtocolAddress(remoteUserId, 1))
            ?: return result.error(
                "NO_IDENTITY",
                "No identity key on file for $remoteUserId — exchange a message first",
                null
            )
        store.recordVerified(remoteUserId, identity)
        result.success(null)
    }

    // ── History ───────────────────────────────────────────────────────────────

    /**
     * Peers to show in the conversation list: those with a live session,
     * plus any with stored history. The two can differ — a burned
     * conversation drops the session, and history predates a session
     * rebuild after a reinstall.
     */
    private fun handleKnownPeers(result: Result) {
        val fromSessions = protocolStore?.knownPeers() ?: emptyList()
        val fromHistory = messageStore?.conversations() ?: emptyList()
        result.success((fromSessions + fromHistory).distinct().sorted())
    }

    private fun handleLoadHistory(call: MethodCall, result: Result) {
        val peer = call.argument<String>("peer")!!
        val entries = messageStore?.history(peer) ?: emptyList()
        result.success(entries.map { json ->
            mapOf(
                "id" to json.optString("id"),
                "peer" to json.optString("peer"),
                "senderId" to json.optString("senderId"),
                "body" to json.optString("body"),
                "ts" to json.optLong("ts"),
                "outgoing" to json.optBoolean("outgoing"),
            )
        })
    }

    private fun handleAppendHistory(call: MethodCall, result: Result) {
        messageStore?.append(
            id = call.argument<String>("id")!!,
            peer = call.argument<String>("peer")!!,
            senderId = call.argument<String>("senderId")!!,
            body = call.argument<String>("body")!!,
            timestampMs = (call.argument<Number>("ts") ?: 0).toLong(),
            outgoing = call.argument<Boolean>("outgoing") ?: false,
        )
        result.success(null)
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

    /**
     * Burning drops the session and this conversation's stored history.
     *
     * It deliberately leaves any out-of-band *verification* in place: the
     * user met this person and confirmed their key, and discarding a
     * conversation is not a reason to un-decide that. Keeping it means a
     * rebuilt session still refuses a substituted key.
     */
    private fun handleBurnConversation(call: MethodCall, result: Result) {
        val store = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        store.burnConversation(remoteUserId)
        messageStore?.deleteConversation(remoteUserId)
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
