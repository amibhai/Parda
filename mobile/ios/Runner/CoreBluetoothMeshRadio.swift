import CoreBluetooth
import Flutter

// ============================================================================
// NEVER COMPILED. NEVER RUN. See the identical warning at the top of
// SignalPlugin.swift — it applies here unchanged. This file additionally
// documents CoreBluetooth's background-mode restrictions precisely,
// which is Sub-Phase 4.5C's other explicit deliverable for iOS.
// ============================================================================

/// PARDA offline-mesh plugin for iOS — mirrors `MeshPlugin.kt`'s
/// method-channel contract (`com.parda.app/mesh`). Implements
/// advertise/scan/GATT via `CBPeripheralManager`/`CBCentralManager`, the
/// same roles `MeshBridge.kt` implements via
/// `BluetoothLeAdvertiser`/`BluetoothLeScanner`/`BluetoothGattServer`.
/// There is no Rust JNI bridge on iOS — Swift/Objective-C interop with a
/// Rust `cdylib` uses a C-ABI FFI bridge instead (bridging headers +
/// `dlopen`/static linking), a different mechanism than JNI's, not
/// attempted in this file: this class stands alone, reasoned as what the
/// *native BLE half* would need to do, matching the same scope boundary
/// `docs/phase4.5c-dart-plaintext-design.md` draws for the Dart FFI
/// design (design first, one platform's wiring actually attempted).
public class MeshPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "com.parda.app/mesh", binaryMessenger: registrar.messenger())
        let instance = MeshPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    private let radio = CoreBluetoothMeshRadio()

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "startMesh":
            radio.start()
            result(nil)
        case "stopMesh":
            radio.stop()
            result(nil)
        default:
            result(FlutterMethodNotImplemented)
        }
    }
}

/// ## Background-mode restrictions, precisely — the specific finding this
/// sub-phase adds to what Phase 4 already documented
///
/// Phase 4's `mesh/src/radio/mod.rs` docs already state the *foreground*
/// restriction: iOS assigns a random per-app `CBPeripheral` UUID instead
/// of exposing a MAC, and rotates the real link-layer address on its own
/// ~15-minute OS schedule with zero app control. **What this sub-phase
/// adds, confirmed against Apple's own Core Bluetooth background
/// processing documentation, not assumed:** while an app is
/// *backgrounded*, iOS strips a peripheral's advertisement down to the
/// service-UUID overflow area only — no service data, no local name
/// survive into a background advertisement. This is more severe than the
/// foreground case: it means `AdvertToken`'s actual payload (the
/// rotating random bytes carrying the "opaque presence beacon" this
/// project's whole rotation design depends on) **cannot be advertised at
/// all while backgrounded on iOS.** Only a pre-registered, static 16-bit
/// service UUID remains visible in that state, discoverable solely by
/// other iOS devices using CoreBluetooth's State Preservation/Restoration
/// background-scan mechanism for that same UUID — and a static UUID
/// with no rotating payload alongside it is, on its own, exactly the
/// "persistent radio-layer identifier" this project's Sub-Phase 4A
/// standard exists to prohibit.
///
/// **Consequence, stated directly:** mesh mode's actual behavior on iOS
/// would necessarily differ between foreground (full opaque-token
/// rotation, matching every other platform) and background (either no
/// advertising at all, or an advertisement that's identifiable as "some
/// PARDA node" via the static service UUID without carrying the rotating
/// token — a strictly weaker guarantee than foreground, not a variant of
/// the same one). No software fix changes this; it is an iOS platform
/// policy, not an implementation gap. This is not attempted to be solved
/// here — recorded precisely, in the same commit as the bridge, per the
/// brief's explicit instruction not to let a background-mode limitation
/// be "discovered later."
class CoreBluetoothMeshRadio: NSObject {
    private var peripheralManager: CBPeripheralManager?
    private var centralManager: CBCentralManager?
    private let serviceUUID = CBUUID(string: "50415244-4134-0000-0000-000000000201")
    private let characteristicUUID = CBUUID(string: "50415244-4134-0000-0000-000000000202")

    func start() {
        peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    func stop() {
        peripheralManager?.stopAdvertising()
        centralManager?.stopScan()
        peripheralManager = nil
        centralManager = nil
    }

    private func currentToken() -> Data {
        // Real implementation would call into the same rotation logic
        // `mesh::radio::RotatingIdentity` already implements on the Rust
        // side — via a C-ABI FFI bridge, not shown here (see file header).
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
}

extension CoreBluetoothMeshRadio: CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheral.state == .poweredOn else { return }
        let characteristic = CBMutableCharacteristic(
            type: characteristicUUID,
            properties: [.write, .notify],
            value: nil,
            permissions: [.writeable]
        )
        let service = CBMutableService(type: serviceUUID, primary: true)
        service.characteristics = [characteristic]
        peripheral.add(service)

        // `CBAdvertisementDataServiceDataKey` is NOT actually supported
        // by `CBPeripheralManager.startAdvertising` — iOS only lets a
        // peripheral advertise `CBAdvertisementDataLocalNameKey` and
        // `CBAdvertisementDataServiceUUIDsKey`, confirmed against
        // Apple's own `startAdvertising(_:)` documentation. This is a
        // second, foreground-applicable restriction beyond the
        // background one documented above: **iOS peripherals cannot
        // advertise arbitrary service-data payloads at all, foreground
        // or background** — only a service UUID list and, optionally, a
        // local name (which this design already refuses to set, per
        // Sub-Phase 4A's "no device name" rule). This means the
        // AdvertToken payload this design relies on elsewhere would need
        // to move to a GATT characteristic read rather than the
        // advertisement packet itself on iOS specifically — a real,
        // platform-specific architecture difference this file surfaces
        // by attempting the real API, not a detail that would have been
        // visible from reasoning about Android/Linux alone.
        peripheral.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [serviceUUID]
        ])
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            // Deliver to the mesh relay agent via FFI — not shown, see
            // file header.
            peripheral.respond(to: request, withResult: .success)
        }
    }
}

extension CoreBluetoothMeshRadio: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else { return }
        central.scanForPeripherals(withServices: [serviceUUID], options: nil)
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        // Per the finding above, `advertisementData` will not carry a
        // service-data token on iOS — the real implementation would need
        // to `connect(peripheral)` and read the characteristic value
        // directly to recover the token, an extra round-trip Android/
        // Linux don't need. Not implemented here — see file header.
        central.connect(peripheral, options: nil)
    }
}
