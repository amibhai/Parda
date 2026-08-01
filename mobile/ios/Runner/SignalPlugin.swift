import Flutter
import UIKit
// LibSignalClient — Signal Foundation's real, published Swift package
// (github.com/signalapp/libsignal, the same monorepo/tag family this
// project's Rust `protocol` crate and Android `libsignal-android`
// dependency already come from — see build.gradle.kts's own note on why
// the Android artifact version doesn't match the Rust git tag exactly).
// Referenced here by its real package name; this file has never been
// added to an Xcode project or resolved by Swift Package Manager — see
// the file-level warning below.
import LibSignalClient

// ============================================================================
// NEVER COMPILED. NEVER RUN. Written Sub-Phase 4.5C, on a Windows machine
// with no Xcode, no macOS, and no path to either — a categorical, not
// incidental, gap (see docs/THREAT_MODEL.md §3.7 and the README
// limitations table). This is a materially WEAKER claim than even the
// unverified Sub-Phase 3C Kotlin fix: that fix edited an existing,
// previously-compiling file without a toolchain to re-verify it; this
// file has no prior compiling version and no toolchain path to ever
// gain one in this environment. Written by close, careful reading of
// LibSignalClient's real public Swift API (github.com/signalapp/libsignal,
// java/swift bindings share the same underlying Rust core this project's
// `protocol` crate already pins) and by mirroring
// `SignalPlugin.kt`'s method-channel contract and behavior exactly, not
// by inventing an API surface. Treat every line below as "reasoned
// against real documentation," never as "verified."
// ============================================================================

/// PARDA Signal Protocol plugin for iOS — mirrors `SignalPlugin.kt`'s
/// method-channel contract exactly (`com.parda.app/signal`), so
/// `signal_bridge.dart` needs no platform-specific branching.
///
/// Swift's `LibSignalClient` package models identity/session state via
/// protocol-oriented stores (`IdentityKeyStore`, `PreKeyStore`,
/// `SignedPreKeyStore`, `SessionStore`) a conforming type must implement,
/// rather than Java's single `InMemorySignalProtocolStore` class —
/// structurally different from `SignalPlugin.kt`, not a smaller feature
/// set; `InMemorySignalProtocolStore` below is this file's equivalent
/// conforming type.
public class SignalPlugin: NSObject, FlutterPlugin {
    private var store: InMemorySignalProtocolStore?
    private let deviceId: UInt32 = 1

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "com.parda.app/signal", binaryMessenger: registrar.messenger())
        let instance = SignalPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "generateIdentity":
            handleGenerateIdentity(call, result: result)
        case "getPreKeyBundle":
            result(["registered": true])
        case "processPreKeyBundle":
            handleProcessPreKeyBundle(call, result: result)
        case "encryptMessage":
            handleEncryptMessage(call, result: result)
        case "decryptMessage":
            handleDecryptMessage(call, result: result)
        case "hasSession":
            handleHasSession(call, result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - generateIdentity

    private func handleGenerateIdentity(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let registrationId = args["registrationId"] as? UInt32 else {
            result(FlutterError(code: "BAD_ARGS", message: "registrationId required", details: nil))
            return
        }

        let identityKeyPair = IdentityKeyPair.generate()
        let signedPreKeyId: UInt32 = 1
        let signedPreKeyPair = PrivateKey.generate()
        let signedPreKeySignature = identityKeyPair.privateKey.generateSignature(
            message: Data(signedPreKeyPair.publicKey.serialize())
        )

        // Real Android equivalent (SignalPlugin.kt) hit exactly this gap:
        // KeyHelper.generatePreKeys(start, count) does not exist in the
        // modern libsignal API at the git tag this project already pins
        // (v0.66.0, confirmed by reading KeyHelper.java directly) — only
        // manual construction does. Applying that same finding here
        // rather than assuming Swift's API kept a convenience method
        // Java's doesn't have.
        let oneTimePreKeys: [(id: UInt32, key: PrivateKey)] = (0..<100).map { id in
            (UInt32(id), PrivateKey.generate())
        }

        self.store = InMemorySignalProtocolStore(
            identity: identityKeyPair,
            registrationId: registrationId
        )
        do {
            try store?.storeSignedPreKey(
                signedPreKeyId,
                signedPreKey: SignedPreKeyRecord(
                    id: signedPreKeyId,
                    timestamp: UInt64(Date().timeIntervalSince1970 * 1000),
                    privateKey: signedPreKeyPair,
                    signature: signedPreKeySignature
                )
            )
            for entry in oneTimePreKeys {
                try store?.storePreKey(entry.id, preKey: PreKeyRecord(id: entry.id, privateKey: entry.key))
            }
        } catch {
            result(FlutterError(code: "SIGNAL_ERROR", message: "\(error)", details: nil))
            return
        }

        let firstPreKey = oneTimePreKeys[0]
        result([
            "registration_id": registrationId,
            "device_id": deviceId,
            "identity_key": identityKeyPair.identityKey.publicKey.serialize().base64EncodedString(),
            "signed_prekey_id": signedPreKeyId,
            "signed_prekey_public": signedPreKeyPair.publicKey.serialize().base64EncodedString(),
            "signed_prekey_signature": signedPreKeySignature.base64EncodedString(),
            "one_time_prekey_id": firstPreKey.id,
            "one_time_prekey_public": firstPreKey.key.publicKey.serialize().base64EncodedString(),
        ])
    }

    // MARK: - processPreKeyBundle

    private func handleProcessPreKeyBundle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let store = store,
              let args = call.arguments as? [String: Any],
              let remoteUserId = args["remoteUserId"] as? String,
              let bundleMap = args["bundle"] as? [String: Any] else {
            result(FlutterError(code: "NOT_ENROLLED", message: "call generateIdentity first", details: nil))
            return
        }
        do {
            let address = ProtocolAddress(name: remoteUserId, deviceId: deviceId)
            let identityKeyBytes = Data(base64Encoded: bundleMap["identity_key"] as! String)!
            let identityKey = try IdentityKey(bytes: identityKeyBytes)
            let signedPreKeyPubBytes = Data(base64Encoded: bundleMap["signed_prekey_public"] as! String)!
            let signedPreKeyPublic = try PublicKey(signedPreKeyPubBytes)
            let signature = Data(base64Encoded: bundleMap["signed_prekey_signature"] as! String)!

            var oneTimePreKeyId: UInt32? = nil
            var oneTimePreKeyPublic: PublicKey? = nil
            if let idNum = bundleMap["one_time_prekey_id"] as? UInt32,
               let pubStr = bundleMap["one_time_prekey_public"] as? String,
               let pubBytes = Data(base64Encoded: pubStr) {
                oneTimePreKeyId = idNum
                oneTimePreKeyPublic = try PublicKey(pubBytes)
            }

            let bundle = try PreKeyBundle(
                registrationId: bundleMap["registration_id"] as! UInt32,
                deviceId: deviceId,
                prekeyId: oneTimePreKeyId,
                prekey: oneTimePreKeyPublic,
                signedPrekeyId: bundleMap["signed_prekey_id"] as! UInt32,
                signedPrekey: signedPreKeyPublic,
                signedPrekeySignature: signature,
                identity: identityKey
            )
            try processPreKeyBundle(bundle, for: address, sessionStore: store, identityStore: store, context: NullContext())
            result(nil)
        } catch {
            result(FlutterError(code: "SIGNAL_ERROR", message: "\(error)", details: nil))
        }
    }

    // MARK: - encryptMessage

    private func handleEncryptMessage(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let store = store,
              let args = call.arguments as? [String: Any],
              let remoteUserId = args["remoteUserId"] as? String,
              let plaintextData = args["plaintext"] as? FlutterStandardTypedData else {
            result(FlutterError(code: "NOT_ENROLLED", message: "call generateIdentity first", details: nil))
            return
        }
        // Sub-Phase 3C mobile-bridge audit finding, applied here too:
        // `plaintextData.data` is an unmanaged copy crossing the platform
        // channel boundary — nothing clears it once libsignal has
        // consumed it. `defer` runs on every exit path, matching
        // SignalPlugin.kt's `finally` block exactly (same reasoning:
        // FlutterMethodChannel encodes the *result* synchronously before
        // this function returns, so zeroizing the source buffer
        // afterward doesn't corrupt what's already been sent).
        var plaintextBytes = [UInt8](plaintextData.data)
        defer { for i in plaintextBytes.indices { plaintextBytes[i] = 0 } }

        do {
            let address = ProtocolAddress(name: remoteUserId, deviceId: deviceId)
            let ciphertext = try signalEncrypt(
                message: Data(plaintextBytes), for: address,
                sessionStore: store, identityStore: store, context: NullContext()
            )
            let envelopeType = ciphertext.messageType == .preKey ? "pre_key" : "ratchet"
            result([
                "sender_id": "local",
                "recipient_id": remoteUserId,
                "ciphertext": ciphertext.serialize().base64EncodedString(),
                "envelope_type": envelopeType,
                "timestamp_ms": UInt64(Date().timeIntervalSince1970 * 1000),
                "sealed_sender": false,
            ])
        } catch {
            result(FlutterError(code: "SIGNAL_ERROR", message: "\(error)", details: nil))
        }
    }

    // MARK: - decryptMessage

    private func handleDecryptMessage(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let store = store,
              let args = call.arguments as? [String: Any],
              let envelope = args["envelope"] as? [String: Any],
              let senderId = envelope["sender_id"] as? String,
              let envelopeType = envelope["envelope_type"] as? String,
              let ciphertextB64 = envelope["ciphertext"] as? String,
              let ciphertextBytes = Data(base64Encoded: ciphertextB64) else {
            result(FlutterError(code: "NOT_ENROLLED", message: "call generateIdentity first", details: nil))
            return
        }
        do {
            let address = ProtocolAddress(name: senderId, deviceId: deviceId)
            var plaintext: [UInt8]
            if envelopeType == "pre_key" {
                let message = try PreKeySignalMessage(bytes: ciphertextBytes)
                plaintext = try signalDecryptPreKey(
                    message: message, from: address, sessionStore: store, identityStore: store,
                    preKeyStore: store, signedPreKeyStore: store, context: NullContext()
                )
            } else {
                let message = try SignalMessage(bytes: ciphertextBytes)
                plaintext = try signalDecrypt(message: message, from: address, sessionStore: store, identityStore: store, context: NullContext())
            }
            // Same finding as encryptMessage, more consequential here —
            // see design note docs/phase4.5c-dart-plaintext-design.md
            // for why *this* copy is exactly the boundary that note's
            // PlaintextHandle design is meant to replace once wired in;
            // this file predates that wiring and still hands Dart a
            // plain FlutterStandardTypedData, the same gap
            // SignalPlugin.kt's decryptMessage has before Sub-Phase 4.5C's
            // Dart-side change lands.
            let plaintextData = Data(plaintext)
            defer { for i in plaintext.indices { plaintext[i] = 0 } }
            result(FlutterStandardTypedData(bytes: plaintextData))
        } catch {
            result(FlutterError(code: "SIGNAL_ERROR", message: "\(error)", details: nil))
        }
    }

    // MARK: - hasSession

    private func handleHasSession(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let store = store,
              let args = call.arguments as? [String: Any],
              let remoteUserId = args["remoteUserId"] as? String else {
            result(false)
            return
        }
        let address = ProtocolAddress(name: remoteUserId, deviceId: deviceId)
        result((try? store.loadSession(for: address, context: NullContext())) != nil)
    }
}

// `InMemorySignalProtocolStore` (conforming to LibSignalClient's
// `IdentityKeyStore`/`PreKeyStore`/`SignedPreKeyStore`/`SessionStore`
// protocols) is intentionally not written out in full here — it would be
// several hundred more lines of equally uncompiled, equally unverifiable
// code implementing the same in-memory bookkeeping
// `protocol/src/store.rs`'s `InMemorySignalProtocolStore` already does on
// the Rust side. Writing it in full would not make this file more
// verified, only longer; the honest scope of this file is "the
// method-channel contract and crypto call shape are reasoned through
// end-to-end against the real API," not "every supporting type is
// spelled out." A real implementation effort would start from
// LibSignalClient's own `InMemorySignalProtocolStore` reference/test
// helper (the library ships one for exactly this purpose) rather than
// reinventing it.
