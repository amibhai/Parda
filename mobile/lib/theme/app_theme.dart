import 'package:flutter/material.dart';

/// Design tokens for the PARDA client.
///
/// Centralised so the palette is defined once rather than as scattered
/// `Color(0xFF...)` literals — the previous screens each repeated the
/// same six hex values, which is how a UI drifts out of sync with
/// itself. Naming is semantic (what a colour *means*) rather than
/// literal (what it looks like), so a future palette change does not
/// require re-reading every call site.
class AppColors {
  AppColors._();

  /// Page background — the darkest surface.
  static const bg = Color(0xFF0D1117);

  /// Raised surface: app bars, cards, input fills.
  static const surface = Color(0xFF161B22);

  /// A surface raised above [surface] — bubbles, chips, list rows.
  static const surfaceHigh = Color(0xFF21262D);

  /// Hairline borders and dividers.
  static const border = Color(0xFF30363D);

  /// Brand green. Reserved for *security-positive* states — verified,
  /// encrypted, connected. Deliberately not used as a generic accent, so
  /// its presence carries meaning.
  static const secure = Color(0xFF00D084);

  /// Brand blue. Outgoing messages and neutral emphasis.
  static const accent = Color(0xFF0066FF);

  /// Failure, destructive actions, unverified-identity warnings.
  static const danger = Color(0xFFDA3633);

  /// Caution: degraded-but-working states (mesh only, TOFU trust).
  static const warning = Color(0xFFD29922);

  static const textPrimary = Color(0xFFE6EDF3);
  static const textSecondary = Color(0xFF8B949E);
  static const textMuted = Color(0xFF6E7681);

  static const brandGradient = LinearGradient(
    colors: [secure, accent],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );
}

class AppTheme {
  AppTheme._();

  static ThemeData dark() {
    const scheme = ColorScheme.dark(
      primary: AppColors.secure,
      secondary: AppColors.accent,
      surface: AppColors.surface,
      error: AppColors.danger,
      onPrimary: Colors.black,
      onSurface: AppColors.textPrimary,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: AppColors.bg,
      appBarTheme: const AppBarTheme(
        backgroundColor: AppColors.surface,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        titleTextStyle: TextStyle(
          color: AppColors.textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
        iconTheme: IconThemeData(color: AppColors.textPrimary),
      ),
      dividerTheme: const DividerThemeData(color: AppColors.border, thickness: 1, space: 1),
      cardTheme: CardThemeData(
        color: AppColors.surface,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: const BorderSide(color: AppColors.border),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.secure,
          foregroundColor: Colors.black,
          disabledBackgroundColor: AppColors.surfaceHigh,
          disabledForegroundColor: AppColors.textMuted,
          padding: const EdgeInsets.symmetric(vertical: 16),
          textStyle: const TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(foregroundColor: AppColors.secure),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.bg,
        hintStyle: const TextStyle(color: AppColors.textMuted),
        contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
        border: _inputBorder(AppColors.border),
        enabledBorder: _inputBorder(AppColors.border),
        focusedBorder: _inputBorder(AppColors.secure),
        errorBorder: _inputBorder(AppColors.danger),
        focusedErrorBorder: _inputBorder(AppColors.danger),
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: AppColors.surfaceHigh,
        contentTextStyle: const TextStyle(color: AppColors.textPrimary),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
      listTileTheme: const ListTileThemeData(
        textColor: AppColors.textPrimary,
        iconColor: AppColors.textSecondary,
      ),
      bottomSheetTheme: const BottomSheetThemeData(
        backgroundColor: AppColors.surface,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: AppColors.surface,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      ),
    );
  }

  static OutlineInputBorder _inputBorder(Color color) => OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide(color: color),
      );
}

/// The PARDA mark — a gradient rounded square with a shield.
class BrandMark extends StatelessWidget {
  final double size;
  final bool glow;

  const BrandMark({super.key, this.size = 32, this.glow = false});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        gradient: AppColors.brandGradient,
        borderRadius: BorderRadius.circular(size * 0.28),
        boxShadow: glow
            ? [
                BoxShadow(
                  color: AppColors.secure.withValues(alpha: 0.35),
                  blurRadius: size * 0.5,
                  spreadRadius: size * 0.08,
                ),
              ]
            : null,
      ),
      child: Icon(Icons.shield, color: Colors.white, size: size * 0.55),
    );
  }
}

/// A small pill used for status ("Encrypted", "Mesh", "Verified").
class StatusPill extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;

  const StatusPill({
    super.key,
    required this.icon,
    required this.label,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: color),
          const SizedBox(width: 5),
          Text(
            label,
            style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600),
          ),
        ],
      ),
    );
  }
}
