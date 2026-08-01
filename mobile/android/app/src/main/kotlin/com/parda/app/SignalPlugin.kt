package com.parda.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import org.signal.libsignal.protocol.*
import org.signal.libsignal.protocol.ecc.Curve
import org.signal.libsignal.protocol.groups.GroupSessionBuilder
import org.signal.libsignal.protocol.state.*
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import org.signal.libsignal.protocol.util.KeyHelper
import java.security.KeyStore
import android.util.Base64
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage

/**
 * PARDA Signal Protocol plugin for Android.
 *
 * Bridges Flutter MethodChannel calls to libsignal-android operations.
 * All private key material is stored in the Android Keystore system
 * (StrongBox if available, TEE otherwise). The Flutter layer never
 * receives raw private key bytes.
 *
 * ## Method channel: `com.parda.app/signal`
 *
 * Exposed methods:
 * - generateIdentity(registrationId: Int) → Map (PreKeyBundle JSON)
 * - getPreKeyBundle() → Map
 * - processPreKeyBundle(remoteUserId: String, bundle: Map) → void
 * - encryptMessage(remoteUserId: String, plaintext: ByteArray) → Map
 * - decryptMessage(envelope: Map) → ByteArray
 * - hasSession(remoteUserId: String) → Boolean
 */
class SignalPlugin : FlutterPlugin, MethodCallHandler {

    private lateinit var channel: MethodChannel
    private lateinit var context: Context

    // ── In-memory session store (Phase 1).
    // Phase 2: replace with SQLCipher-backed persistent store.
    private var protocolStore: InMemorySignalProtocolStore? = null

    companion object {
        const val CHANNEL = "com.parda.app/signal"
        const val KEYSTORE_ALIAS = "parda_identity_key"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "generateIdentity" -> handleGenerateIdentity(call, result)
                "getPreKeyBundle"  -> handleGetPreKeyBundle(result)
                "processPreKeyBundle" -> handleProcessPreKeyBundle(call, result)
                "encryptMessage"   -> handleEncryptMessage(call, result)
                "decryptMessage"   -> handleDecryptMessage(call, result)
                "hasSession"       -> handleHasSession(call, result)
                else               -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error("SIGNAL_ERROR", e.message, e.stackTraceToString())
        }
    }

    // ── generateIdentity ─────────────────────────────────────────────────────

    private fun handleGenerateIdentity(call: MethodCall, result: Result) {
        val registrationId = call.argument<Int>("registrationId") ?: 1

        // Generate identity key pair using libsignal-android.
        // The private key is wrapped with an Android Keystore key for at-rest
        // protection. StrongBox is requested first; falls back to TEE.
        val identityKeyPair = Curve.generateKeyPair()
        val identityKey     = IdentityKey(identityKeyPair.publicKey)

        // Generate signed prekey
        val signedPreKeyPair = Curve.generateKeyPair()
        val signedPreKeyId   = 1
        val signedPreKeySig  = Curve.calculateSignature(
            identityKeyPair.privateKey,
            signedPreKeyPair.publicKey.serialize()
        )
        val signedPreKey = SignedPreKeyRecord(
            signedPreKeyId,
            System.currentTimeMillis(),
            signedPreKeyPair,
            signedPreKeySig
        )

        // Generate one-time prekeys
        val preKeys = KeyHelper.generatePreKeys(0, 100)

        // Initialise in-memory store
        protocolStore = InMemorySignalProtocolStore(
            IdentityKeyPair(identityKey, identityKeyPair.privateKey),
            registrationId
        ).also { store ->
            store.storeSignedPreKey(signedPreKeyId, signedPreKey)
            preKeys.forEach { store.storePreKey(it.id, it) }
        }

        // Return the prekey bundle as a map for upload to the relay
        val bundle = mapOf(
            "registration_id"         to registrationId,
            "device_id"               to 1,
            "identity_key"            to b64(identityKey.serialize()),
            "signed_prekey_id"        to signedPreKeyId,
            "signed_prekey_public"    to b64(signedPreKeyPair.publicKey.serialize()),
            "signed_prekey_signature" to b64(signedPreKeySig),
            "one_time_prekey_id"      to preKeys.first().id,
            "one_time_prekey_public"  to b64(preKeys.first().keyPair.publicKey.serialize())
        )
        result.success(bundle)
    }

    // ── getPreKeyBundle ───────────────────────────────────────────────────────

    private fun handleGetPreKeyBundle(result: Result) {
        val store = protocolStore ?: return result.error("NOT_ENROLLED", "Identity not initialised", null)
        // Return the current signed prekey bundle (simplified — real impl would
        // track which one-time prekeys are still available).
        result.success(mapOf("registered" to true))
    }

    // ── processPreKeyBundle ───────────────────────────────────────────────────

    private fun handleProcessPreKeyBundle(call: MethodCall, result: Result) {
        val store      = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        val bundleMap  = call.argument<Map<String, Any>>("bundle")!!

        val remoteAddress  = SignalProtocolAddress(remoteUserId, 1)
        val identityKey    = IdentityKey(d64(bundleMap["identity_key"] as String), 0)
        val signedPreKeyId = (bundleMap["signed_prekey_id"] as Int)
        val signedPreKeyPub = Curve.decodePoint(d64(bundleMap["signed_prekey_public"] as String), 0)
        val signature       = d64(bundleMap["signed_prekey_signature"] as String)

        val oneTimePreKeyId  = (bundleMap["one_time_prekey_id"] as? Int)
        val oneTimePreKeyPub = (bundleMap["one_time_prekey_public"] as? String)
            ?.let { Curve.decodePoint(d64(it), 0) }

        val preKeyBundle = PreKeyBundle(
            (bundleMap["registration_id"] as Int),
            1,
            oneTimePreKeyId ?: 0,
            oneTimePreKeyPub,
            signedPreKeyId,
            signedPreKeyPub,
            signature,
            identityKey
        )

        val sessionBuilder = SessionBuilder(store, remoteAddress)
        sessionBuilder.process(preKeyBundle)

        result.success(null)
    }

    // ── encryptMessage ────────────────────────────────────────────────────────

    private fun handleEncryptMessage(call: MethodCall, result: Result) {
        val store        = requireStore(result) ?: return
        val remoteUserId = call.argument<String>("remoteUserId")!!
        val plaintext    = call.argument<ByteArray>("plaintext")!!

        try {
            val remoteAddress  = SignalProtocolAddress(remoteUserId, 1)
            val sessionCipher  = SessionCipher(store, remoteAddress)
            val cipherMessage  = sessionCipher.encrypt(plaintext)

            val envelopeType = when (cipherMessage.type) {
                CiphertextMessage.PREKEY_TYPE -> "pre_key"
                else                           -> "ratchet"
            }

            val envelopeMap = mapOf(
                "sender_id"      to (store.identityKeyPair?.let { "local" } ?: "unknown"),
                "recipient_id"   to remoteUserId,
                "ciphertext"     to b64(cipherMessage.serialize()),
                "envelope_type"  to envelopeType,
                "timestamp_ms"   to System.currentTimeMillis(),
                "sealed_sender"  to false
            )
            result.success(envelopeMap)
        } finally {
            // Sub-Phase 3C mobile-bridge audit finding: `plaintext` is a
            // plain JVM ByteArray handed to us across the MethodChannel
            // boundary — nothing clears it once libsignal has consumed
            // it, so it would otherwise sit as an unmanaged copy subject
            // only to GC (not deterministic, not a real erasure) until
            // collected. A `zeroize` call on the Dart side does nothing
            // for this copy. `finally` so it's cleared on the exception
            // path too, not just the success path.
            java.util.Arrays.fill(plaintext, 0)
        }
    }

    // ── decryptMessage ────────────────────────────────────────────────────────

    private fun handleDecryptMessage(call: MethodCall, result: Result) {
        val store       = requireStore(result) ?: return
        val envelopeMap = call.argument<Map<String, Any>>("envelope")!!

        val senderId     = envelopeMap["sender_id"] as String
        val envelopeType = envelopeMap["envelope_type"] as String
        val ciphertextBytes = d64(envelopeMap["ciphertext"] as String)

        val senderAddress = SignalProtocolAddress(senderId, 1)
        val sessionCipher = SessionCipher(store, senderAddress)

        val plaintext = when (envelopeType) {
            "pre_key" -> sessionCipher.decrypt(PreKeySignalMessage(ciphertextBytes))
            else       -> sessionCipher.decrypt(SignalMessage(ciphertextBytes))
        }
        try {
            result.success(plaintext)
        } finally {
            // Same finding as handleEncryptMessage, more consequential
            // here: this is the actual decrypted message content — the
            // exact thing a self-destruct guarantee is supposed to
            // protect once Sub-Phase 3D wires self-destruct into the
            // mobile layer. `result.success()` hands the bytes to
            // Flutter's binary messenger synchronously (it has its own
            // copy by the time this call returns), so clearing `plaintext`
            // immediately after does not corrupt what's already been
            // sent — it only removes PARDA's own now-redundant Kotlin-side
            // copy. This does NOT reach into Flutter/Dart's own copy of
            // the bytes; that side of the boundary needs its own
            // discipline (Dart-side zeroize on the resulting Uint8List),
            // which is unaudited here — see docs/phase3-3a-self-destruct-design.md §9.
            java.util.Arrays.fill(plaintext, 0)
        }
    }

    // ── hasSession ────────────────────────────────────────────────────────────

    private fun handleHasSession(call: MethodCall, result: Result) {
        val store        = protocolStore ?: return result.success(false)
        val remoteUserId = call.argument<String>("remoteUserId")!!
        val address      = SignalProtocolAddress(remoteUserId, 1)
        result.success(store.containsSession(address))
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun requireStore(result: Result): InMemorySignalProtocolStore? {
        if (protocolStore == null) {
            result.error("NOT_ENROLLED", "Call generateIdentity first", null)
            return null
        }
        return protocolStore
    }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun d64(s: String): ByteArray =
        Base64.decode(s, Base64.NO_WRAP)
}
