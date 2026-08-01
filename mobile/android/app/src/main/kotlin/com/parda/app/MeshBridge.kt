package com.parda.app

import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Real Android BLE backend for `parda_mesh::radio::MeshRadio`
 * (Sub-Phase 4.5B) — the JVM half of the Rust↔JNI bridge. See
 * `mobile-bridge/src/lib.rs` (the Rust crate this loads,
 * `parda_mobile_bridge`) for the overall design.
 *
 * ## Honesty about verification, stated once here rather than per-method
 *
 * Every method below was written against Android's documented
 * `BluetoothLeAdvertiser`/`BluetoothLeScanner`/`BluetoothGattServer`
 * APIs and compiled via a real Gradle build. **Whether it actually
 * advertises/scans/connects over real or emulated (rootcanal) Bluetooth
 * is a separate, weaker claim** — see `docs/THREAT_MODEL.md` §3.7 and
 * the README for exactly how far this session's testing got, reported
 * without rounding up. "Compiles against the real Android SDK" and
 * "verified against real BLE behavior" are different claims; conflating
 * them would violate the same standard this project already holds the
 * Sub-Phase 3C Kotlin fix to.
 *
 * ## Framing over GATT
 *
 * A single characteristic carries both directions: the central
 * (`connect`) writes to it; the peripheral (`accept`) responds via
 * `notifyCharacteristicChanged` after the central subscribes via the
 * standard CCCD descriptor write. This is the conventional full-duplex
 * pattern over one GATT characteristic — not a PARDA invention.
 */
object MeshBridge {
    private const val TAG = "MeshBridge"

    init {
        System.loadLibrary("parda_mobile_bridge")
    }

    /// Fixed, public "this is a PARDA mesh node" service UUID — carries
    /// no per-device information, matching `mesh/src/radio/bluez.rs`'s
    /// `PARDA_SERVICE_UUID` role (same protocol-identification purpose,
    /// deliberately a different UUID value from the Linux backend's,
    /// since the two never need to interoperate directly at the GATT
    /// layer and reusing bytes across unrelated codebases would imply a
    /// coupling that doesn't exist).
    private val SERVICE_UUID: UUID = UUID.fromString("50415244-4134-0000-0000-000000000101")
    private val CHARACTERISTIC_UUID: UUID = UUID.fromString("50415244-4134-0000-0000-000000000102")
    private val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    private lateinit var appContext: Context
    private lateinit var bluetoothManager: BluetoothManager

    private var currentAdvertiseCallback: AdvertiseCallback? = null
    private val scanCallbacks = ConcurrentHashMap<Long, ScanCallback>()
    private var gattServer: BluetoothGattServer? = null
    private val pendingAcceptRequestIds = java.util.concurrent.ConcurrentLinkedQueue<Long>()

    private val nextLinkHandle = AtomicLong(1)
    private val centralLinks = ConcurrentHashMap<Long, BluetoothGatt>()
    private val serverLinks = ConcurrentHashMap<Long, BluetoothDevice>()
    // Pending recv() request IDs waiting on the next inbound
    // write/notification for a given link handle — at most one
    // outstanding recv per link at a time, matching how
    // `parda_mesh::relay::sync_with_peer` only ever awaits one recv
    // before issuing the next.
    private val pendingRecv = ConcurrentHashMap<Long, Long>()

    fun init(context: Context) {
        appContext = context.applicationContext
        bluetoothManager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    }

    // ── Native callback entry points (implemented in Rust; see
    //    mobile-bridge/src/jni_exports.rs) ──────────────────────────────

    @JvmStatic
    external fun nativeOnAdvertiseResult(requestId: Long, success: Boolean, error: String?)
    @JvmStatic
    external fun nativeOnScanResult(streamId: Long, peerHandle: ByteArray, token: ByteArray)
    @JvmStatic
    external fun nativeOnConnectResult(requestId: Long, linkHandle: Long, error: String?)
    @JvmStatic
    external fun nativeOnAcceptResult(requestId: Long, linkHandle: Long, error: String?)
    @JvmStatic
    external fun nativeOnSendResult(requestId: Long, error: String?)
    @JvmStatic
    external fun nativeOnRecvResult(requestId: Long, bytes: ByteArray?, error: String?)

    // ── Calls from Rust (mobile-bridge/src/ffi.rs) ──────────────────────

    @JvmStatic
    fun startAdvertise(requestId: Long, token: ByteArray) {
        val adapter = bluetoothManager.adapter
        val advertiser = adapter?.bluetoothLeAdvertiser
        if (adapter == null || advertiser == null) {
            nativeOnAdvertiseResult(requestId, false, "no BLE advertiser available on this device")
            return
        }
        ensureGattServer()

        // Rotation: a fresh call always fully replaces whatever was
        // previously advertised — see radio module docs on why the
        // *payload* rotating, not any link-layer address this app has
        // no control over regardless, is what this backend can actually
        // guarantee.
        currentAdvertiseCallback?.let { advertiser.stopAdvertising(it) }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .build()
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .addServiceData(ParcelUuid(SERVICE_UUID), token)
            // Never advertise a device name — see radio module docs on
            // why the advertised payload must carry nothing beyond the
            // opaque token.
            .setIncludeDeviceName(false)
            .build()

        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                nativeOnAdvertiseResult(requestId, true, null)
            }
            override fun onStartFailure(errorCode: Int) {
                Log.w(TAG, "advertise failed, code=$errorCode")
                nativeOnAdvertiseResult(requestId, false, "advertise failed, code=$errorCode")
            }
        }
        currentAdvertiseCallback = callback
        advertiser.startAdvertising(settings, data, callback)
    }

    @JvmStatic
    fun startScan(streamId: Long) {
        val adapter = bluetoothManager.adapter
        val scanner = adapter?.bluetoothLeScanner
        if (scanner == null) {
            // No result will ever arrive for this stream — the Rust
            // side's deadline (see mobile-bridge/src/radio.rs) times out
            // to an empty snapshot rather than hanging forever, so no
            // separate error signal is needed here.
            Log.w(TAG, "no BLE scanner available on this device")
            return
        }
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_BALANCED).build()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val serviceData = result.scanRecord?.getServiceData(ParcelUuid(SERVICE_UUID)) ?: return
                val peerHandle = result.device.address.toByteArray(Charsets.UTF_8)
                nativeOnScanResult(streamId, peerHandle, serviceData)
            }
            override fun onScanFailed(errorCode: Int) {
                Log.w(TAG, "scan failed, code=$errorCode")
            }
        }
        scanCallbacks[streamId] = callback
        scanner.startScan(listOf(filter), settings, callback)
    }

    @JvmStatic
    fun stopScan(streamId: Long) {
        val scanner = bluetoothManager.adapter?.bluetoothLeScanner ?: return
        scanCallbacks.remove(streamId)?.let { scanner.stopScan(it) }
    }

    @JvmStatic
    fun connect(requestId: Long, peerHandle: ByteArray) {
        val adapter = bluetoothManager.adapter
        val address = String(peerHandle, Charsets.UTF_8)
        val device = try {
            adapter?.getRemoteDevice(address)
        } catch (e: IllegalArgumentException) {
            null
        }
        if (device == null) {
            nativeOnConnectResult(requestId, 0, "invalid or unreachable peer address")
            return
        }

        val gattCallback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    gatt.discoverServices()
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    val handle = centralLinks.entries.find { it.value == gatt }?.key
                    handle?.let { centralLinks.remove(it) }
                }
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    nativeOnConnectResult(requestId, 0, "service discovery failed, status=$status")
                    gatt.close()
                    return
                }
                val characteristic = gatt.getService(SERVICE_UUID)?.getCharacteristic(CHARACTERISTIC_UUID)
                if (characteristic == null) {
                    nativeOnConnectResult(requestId, 0, "PARDA characteristic not found on peer")
                    gatt.close()
                    return
                }
                // Subscribe to notifications — how this side's recv()
                // calls will actually receive bytes the peer sends back.
                gatt.setCharacteristicNotification(characteristic, true)
                val cccd = characteristic.getDescriptor(CCCD_UUID)
                if (cccd != null) {
                    @Suppress("DEPRECATION")
                    cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    @Suppress("DEPRECATION")
                    gatt.writeDescriptor(cccd)
                }
                val linkHandle = nextLinkHandle.getAndIncrement()
                centralLinks[linkHandle] = gatt
                nativeOnConnectResult(requestId, linkHandle, null)
            }

            override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
                val handle = centralLinks.entries.find { it.value == gatt }?.key ?: return
                deliverRecv(handle, characteristic.value)
            }

            override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
                val handle = centralLinks.entries.find { it.value == gatt }?.key ?: return
                val pendingId = pendingSend.remove(handle) ?: return
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    nativeOnSendResult(pendingId, null)
                } else {
                    nativeOnSendResult(pendingId, "write failed, status=$status")
                }
            }
        }
        device.connectGatt(appContext, false, gattCallback)
    }

    private val pendingSend = ConcurrentHashMap<Long, Long>() // linkHandle -> requestId

    @JvmStatic
    fun accept(requestId: Long) {
        ensureGattServer()
        pendingAcceptRequestIds.add(requestId)
        // The actual resolution happens in the GATT server callback's
        // onConnectionStateChange (STATE_CONNECTED) — see
        // ensureGattServer() below.
    }

    @JvmStatic
    fun send(requestId: Long, linkHandle: Long, bytes: ByteArray) {
        centralLinks[linkHandle]?.let { gatt ->
            val characteristic = gatt.getService(SERVICE_UUID)?.getCharacteristic(CHARACTERISTIC_UUID)
            if (characteristic == null) {
                nativeOnSendResult(requestId, "characteristic unavailable")
                return
            }
            pendingSend[linkHandle] = requestId
            @Suppress("DEPRECATION")
            characteristic.value = bytes
            @Suppress("DEPRECATION")
            val started = gatt.writeCharacteristic(characteristic)
            if (!started) {
                pendingSend.remove(linkHandle)
                nativeOnSendResult(requestId, "writeCharacteristic failed to start")
            }
            return
        }
        serverLinks[linkHandle]?.let { device ->
            val characteristic = gattServer?.getService(SERVICE_UUID)?.getCharacteristic(CHARACTERISTIC_UUID)
            if (characteristic == null) {
                nativeOnSendResult(requestId, "characteristic unavailable")
                return
            }
            @Suppress("DEPRECATION")
            characteristic.value = bytes
            @Suppress("DEPRECATION")
            val started = gattServer?.notifyCharacteristicChanged(device, characteristic, false) ?: false
            if (started) {
                nativeOnSendResult(requestId, null)
            } else {
                nativeOnSendResult(requestId, "notifyCharacteristicChanged failed to start")
            }
            return
        }
        nativeOnSendResult(requestId, "unknown link handle")
    }

    @JvmStatic
    fun recv(requestId: Long, linkHandle: Long) {
        // Registers interest; delivery happens from
        // onCharacteristicChanged (central side) or
        // onCharacteristicWriteRequest (server side) — see
        // deliverRecv(). At most one outstanding recv per link, matching
        // `MeshRelayAgent::sync_with_peer`'s own request/response
        // pattern (it never issues a second recv before the first
        // resolves).
        pendingRecv[linkHandle] = requestId
    }

    private fun deliverRecv(linkHandle: Long, bytes: ByteArray?) {
        val requestId = pendingRecv.remove(linkHandle) ?: return
        if (bytes == null) {
            nativeOnRecvResult(requestId, null, "no data")
        } else {
            nativeOnRecvResult(requestId, bytes, null)
        }
    }

    // ── GATT server (peripheral role — how accept()/incoming recv() work) ──

    private fun ensureGattServer() {
        if (gattServer != null) return
        val callback = object : BluetoothGattServerCallback() {
            override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    val linkHandle = nextLinkHandle.getAndIncrement()
                    serverLinks[linkHandle] = device
                    val requestId = pendingAcceptRequestIds.poll()
                    if (requestId != null) {
                        nativeOnAcceptResult(requestId, linkHandle, null)
                    }
                    // If no accept() call was pending yet, the link is
                    // still registered — a subsequent accept() will find
                    // no matching request here in this minimal
                    // implementation. Documented residual: a real
                    // deployment would queue unmatched connections the
                    // way mesh::radio::simulated's accept_tx channel
                    // does; not implemented in this session's version.
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    serverLinks.entries.find { it.value == device }?.key?.let { serverLinks.remove(it) }
                }
            }

            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice,
                requestId: Int,
                characteristic: BluetoothGattCharacteristic,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray
            ) {
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
                }
                val linkHandle = serverLinks.entries.find { it.value == device }?.key ?: return
                deliverRecv(linkHandle, value)
            }
        }
        gattServer = bluetoothManager.openGattServer(appContext, callback)
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val characteristic = BluetoothGattCharacteristic(
            CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        val cccd = BluetoothGattDescriptor(
            CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        characteristic.addDescriptor(cccd)
        service.addCharacteristic(characteristic)
        gattServer?.addService(service)
    }
}
