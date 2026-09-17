import 'package:flutter/material.dart';

class SocTheme {
  SocTheme._();

  static const Color background = Color(0xFF0B0F19);
  static const Color surface = Color(0xFF131A2A);
  static const Color surfaceElevated = Color(0xFF1B243B);
  static const Color border = Color(0xFF22314E);
  
  // Status Colors
  static const Color normalGreen = Color(0xFF00E676);
  static const Color lowBlue = Color(0xFF00B0FF);
  static const Color warningAmber = Color(0xFFFFB300);
  static const Color criticalRed = Color(0xFFFF1744);
  
  // Brand / Quantum Colors
  static const Color cyanAccent = Color(0xFF00F0FF);
  static const Color quantumPurple = Color(0xFFB388FF);

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: background,
      colorScheme: const ColorScheme.dark(
        primary: cyanAccent,
        secondary: quantumPurple,
        surface: surface,
        error: criticalRed,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: background,
        elevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          fontSize: 20,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.5,
          color: Colors.white,
        ),
      ),
      cardTheme: CardTheme(
        color: surface,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: border, width: 1),
        ),
      ),
    );
  }

  static Color getRiskColor(double score) {
    if (score < 30) return normalGreen;
    if (score < 60) return lowBlue;
    if (score < 80) return warningAmber;
    return criticalRed;
  }

  static String getRiskLevel(double score) {
    if (score < 30) return 'SAFE';
    if (score < 60) return 'LOW';
    if (score < 80) return 'MEDIUM';
    return 'CRITICAL';
  }
}
