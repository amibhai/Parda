package com.parda.app

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

/**
 * `SignalPlugin` and `MeshPlugin` are hand-authored, in-tree plugins, not
 * separate pub.dev packages — they never appear in the auto-generated
 * `GeneratedPluginRegistrant` (confirmed by reading it: it lists
 * `connectivity_plus`, `flutter_secure_storage`, `jni`, `jni_flutter`,
 * `sqflite_android` only). Registering them explicitly here is required
 * for `SignalBridge`'s and `MeshBridge`'s method channels to have a
 * native-side handler at all — found while scaffolding this file
 * (Sub-Phase 4.5B): before this project had a `MainActivity`, neither
 * plugin could ever actually have been invoked from Dart, regardless of
 * how correct their own code was.
 */
class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MeshBridge.init(applicationContext)
        flutterEngine.plugins.add(SignalPlugin())
        flutterEngine.plugins.add(MeshPlugin())
        flutterEngine.plugins.add(PlaintextPlugin())
    }
}
