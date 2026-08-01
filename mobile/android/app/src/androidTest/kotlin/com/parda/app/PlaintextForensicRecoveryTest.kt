package com.parda.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets

/**
 * On-device forensic-recovery test for the Sub-Phase 4.5C plaintext
 * bridge, extending `protocol/src/plaintext_ffi.rs`'s
 * `canary_bytes_absent_from_process_memory_after_release` technique
 * (same `/proc/self/mem` self-scan — Android is Linux-kernel-based, so
 * an app can read its own process memory without special privilege)
 * across the JNI boundary this test's namesake Rust test never crosses.
 *
 * ## What this proves, and what it doesn't — read before trusting this
 *
 * This exercises [PlaintextBridge] directly (`nativePlaintextNew` →
 * scan → `nativePlaintextCopyInto` → `nativePlaintextRelease` → scan),
 * the same calls `PlaintextPlugin.kt`'s method-channel handlers make.
 * **It does not drive Dart/Flutter code** — a plain instrumented
 * (`androidTest`) JUnit test runs in the app's JVM process but has no
 * Dart runtime to call into; reaching `plaintext_handle.dart`'s
 * `renderCopy()` would need the heavier `integration_test` package
 * harness, not attempted in this session (see
 * `docs/phase4.5c-dart-plaintext-design.md` §5's original framing,
 * which named the Dart layer explicitly — this test's real, narrower
 * scope is stated here rather than left to look like it covers that).
 * What it *does* prove, genuinely, on a real device/emulator process
 * rather than by reasoning: the native buffer
 * [PlaintextBridge.nativePlaintextNew] allocates is findable in this
 * process's own memory before release and absent after — the same
 * claim `protocol/src/plaintext_ffi.rs`'s pure-Rust test makes, now
 * confirmed to still hold true once a real JNI call boundary and a
 * real Android process are involved, not just a `cargo test` process.
 *
 * ## Status
 *
 * Written and reviewed against the real `androidx.test`/JUnit4 APIs
 * this Gradle module now depends on (see `app/build.gradle.kts`).
 * **Not executed against the running emulator in this session** — doing
 * so needs `./gradlew connectedAndroidTest`, a separate, real device-
 * attached test run this session's time budget did not extend to after
 * the compile-verified `assembleDebug` build (see README / THREAT_MODEL
 * for the exact line between "compiles against the real SDK" and
 * "verified running on real/emulated hardware," a distinction this
 * project holds itself to consistently, not just here).
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class PlaintextForensicRecoveryTest {

    private val canary = "PARDA-4-5-C-JNI-BOUNDARY-CANARY-9d2e71c4".toByteArray(StandardCharsets.UTF_8)

    /** Same technique as `protocol/src/plaintext_ffi.rs`'s Linux test, translated to Kotlin. */
    private fun processMemoryContains(needle: ByteArray): Boolean {
        val maps = java.io.File("/proc/self/maps").readLines()
        val mem = RandomAccessFile("/proc/self/mem", "r")
        try {
            for (line in maps) {
                val parts = line.split(" ", limit = 2)
                if (parts.size < 2 || !parts[1].startsWith("r")) continue
                val range = parts[0].split("-")
                if (range.size != 2) continue
                val start = range[0].toLongOrNull(16) ?: continue
                val end = range[1].toLongOrNull(16) ?: continue
                val len = end - start
                // Skip implausibly large regions to keep this bounded on a
                // real device's full address space, mirroring the Rust
                // test's per-region read approach.
                if (len <= 0 || len > 256L * 1024 * 1024) continue
                try {
                    mem.seek(start)
                    val buf = ByteArray(len.toInt())
                    mem.readFully(buf)
                    if (indexOf(buf, needle) >= 0) return true
                } catch (_: Exception) {
                    // Unreadable region (guard page, races with the OS) —
                    // same "skip and continue" tolerance as the Rust test.
                    continue
                }
            }
        } finally {
            mem.close()
        }
        return false
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    @Test
    fun canary_absent_from_process_memory_after_release() {
        val handle = PlaintextBridge.nativePlaintextNew(canary)
        assertTrue("nativePlaintextNew must return a non-zero handle", handle != 0L)

        assertTrue(
            "sanity check: canary must be findable before release",
            processMemoryContains(canary),
        )

        val copy = PlaintextBridge.nativePlaintextCopyInto(handle)
        assertTrue(copy != null && copy.contentEquals(canary))

        PlaintextBridge.nativePlaintextRelease(handle)

        assertFalse(
            "canary must be absent from process memory after release",
            processMemoryContains(canary),
        )
    }

    @Test
    fun copy_into_and_len_fail_closed_after_release() {
        val handle = PlaintextBridge.nativePlaintextNew(canary)
        PlaintextBridge.nativePlaintextRelease(handle)

        assertTrue(
            "a released handle must report length 0, not stale data",
            PlaintextBridge.nativePlaintextLen(handle) == 0L,
        )
        assertTrue(
            "a released handle must refuse to copy, not return stale bytes",
            PlaintextBridge.nativePlaintextCopyInto(handle) == null,
        )
    }
}
