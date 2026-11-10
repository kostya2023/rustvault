import 'dart:async';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import 'error_mapper.dart';

/// English-only application logging with a final redaction pass.
class AppLogger {
  static const _name = 'RustVault';
  static Future<File?>? _logFileFuture;
  static Future<void> _fileWriteChain = Future<void>.value();

  static void debug(String message, {Object? error, StackTrace? stackTrace}) {
    _write(message, 500, error: error, stackTrace: stackTrace);
  }

  static void info(String message, {Object? error, StackTrace? stackTrace}) {
    _write(message, 800, error: error, stackTrace: stackTrace);
  }

  static void warning(String message, {Object? error, StackTrace? stackTrace}) {
    _write(message, 900, error: error, stackTrace: stackTrace);
  }

  static void error(String message, {Object? error, StackTrace? stackTrace}) {
    _write(message, 1000, error: error, stackTrace: stackTrace);
  }

  static void _write(
    String message,
    int level, {
    Object? error,
    StackTrace? stackTrace,
  }) {
    final safeMessage = _redact(message);
    final mappedError = error == null ? null : describeAppErrorForLog(error);
    final fullMessage = mappedError == null
        ? safeMessage
        : '$safeMessage - $mappedError';

    developer.log(
      fullMessage,
      name: _name,
      level: level,
      error: mappedError,
      stackTrace: stackTrace,
    );

    final line =
        '${DateTime.now().toUtc().toIso8601String()} [$level] '
        '$fullMessage${stackTrace == null ? '' : '\n$stackTrace'}\n';
    if (Platform.isWindows || Platform.isLinux) {
      _fileWriteChain = _fileWriteChain.then((_) => _appendDesktopLog(line));
    }
    if (Platform.isAndroid || kDebugMode) {
      // Flutter forwards debugPrint to logcat on Android.
      debugPrint('[RustVault] $fullMessage');
    }
  }

  static Future<void> _appendDesktopLog(String line) async {
    try {
      _logFileFuture ??= _createDesktopLogFile();
      final file = await _logFileFuture!;
      await file?.writeAsString(line, mode: FileMode.append, flush: true);
    } catch (_) {
      // Logging must never break the application.
    }
  }

  static Future<File?> _createDesktopLogFile() async {
    final directory = await getTemporaryDirectory();
    final timestamp = DateTime.now()
        .toUtc()
        .toIso8601String()
        .replaceAll(':', '-')
        .replaceAll('+', 'p');
    return File(
      '${directory.path}${Platform.pathSeparator}rustvault_$timestamp.log',
    );
  }

  static String _redact(String value) {
    final sensitive = RegExp(
      r'''(password|passwd|credential|username|access[_-]?token|refresh[_-]?token|token|secret|authorization|cookie|clipboard|totp|otp|passkey|private[_-]?key|blob)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)''',
      caseSensitive: false,
    );
    return value
        .replaceAllMapped(sensitive, (match) => '${match.group(1)}=<redacted>')
        .replaceAll(
          RegExp(r'Bearer\s+\S+', caseSensitive: false),
          'Bearer <redacted>',
        );
  }
}
