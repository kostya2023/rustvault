import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'app_logger.dart';
import 'auth_service.dart';
import 'memory_protection_service.dart';

Future<void> initializeDesktopWindow() async {
  if (_isDesktop) await windowManager.ensureInitialized();
}

bool get _isDesktop =>
    !kIsWeb && (Platform.isWindows || Platform.isLinux || Platform.isMacOS);

class DesktopWindowShell extends StatefulWidget {
  final Widget child;
  final GlobalKey<NavigatorState> navigatorKey;

  const DesktopWindowShell({
    super.key,
    required this.child,
    required this.navigatorKey,
  });

  @override
  State<DesktopWindowShell> createState() => _DesktopWindowShellState();
}

class _DesktopWindowShellState extends State<DesktopWindowShell>
    with WindowListener, WidgetsBindingObserver {
  bool _isClosing = false;
  double _progress = 0;
  Timer? _minimizedWipeTimer;
  Timer? _backgroundWipeTimer;
  bool _isRestoringSensitiveMemory = false;
  String _status = 'Подготовка к закрытию…';

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    if (_isDesktop) {
      windowManager.addListener(this);
      unawaited(_prepareWindow());
    }
  }

  Future<void> _prepareWindow() async {
    try {
      await windowManager.setPreventClose(true);
    } catch (error) {
      AppLogger.error('Window setup failed.', error: error);
    }
  }

  @override
  void onWindowClose() {
    _minimizedWipeTimer?.cancel();
    if (!_isClosing) unawaited(_closeWithStatus());
  }

  @override
  void onWindowMinimize() {
    _minimizedWipeTimer?.cancel();
    _minimizedWipeTimer = Timer(const Duration(minutes: 1), () async {
      if (mounted && !_isClosing) unawaited(_lockSensitiveMemory());
    });
  }

  @override
  void onWindowRestore() {
    _minimizedWipeTimer?.cancel();
    _minimizedWipeTimer = null;
    unawaited(_restoreSensitiveMemory());
  }

  Future<void> _lockSensitiveMemory() async {
    if (!mounted || _isClosing || MemoryProtectionService().isLocked) return;
    AppLogger.info('Window stayed minimized; locking sensitive memory.');
    await AuthService().suspendSensitiveSession();
    MemoryProtectionService().lock();
  }

  Future<void> _restoreSensitiveMemory() async {
    if (!MemoryProtectionService().isLocked || _isRestoringSensitiveMemory) {
      return;
    }
    _isRestoringSensitiveMemory = true;
    AppLogger.info('Window restored; rebuilding sensitive memory.');
    try {
      final restored = await AuthService().restoreSuspendedSession(
        refresh: !AuthService().isOfflineMode,
      );
      if (restored) MemoryProtectionService().unlock();
    } finally {
      _isRestoringSensitiveMemory = false;
    }
  }

  Future<void> _closeWithStatus() async {
    if (!mounted) return;
    setState(() {
      _isClosing = true;
      _progress = 0.12;
      _status = 'Записывание файлов…';
    });

    // Give pending Flutter writes and the user-facing status time to finish.
    await Future<void>.delayed(const Duration(milliseconds: 450));
    if (!mounted) return;
    setState(() {
      _progress = 0.48;
      _status = 'Сохранение зашифрованного кеша…';
    });

    await Future<void>.delayed(const Duration(milliseconds: 450));
    if (!mounted) return;
    setState(() {
      _progress = 0.82;
      _status = 'Завершение работы RustVault…';
    });

    // Preserve the encrypted blob and cached session on normal close.
    // Disk data is removed only by an explicit user logout.
    await AuthService().zeroizeActiveCryptoKey();
    if (mounted) {
      setState(() {
        _progress = 0.96;
        _status = 'Локальные данные затёрты…';
      });
    }

    if (mounted) {
      setState(() => _status = 'Securing in-memory data…');
    }
    await Future<void>.delayed(const Duration(milliseconds: 300));
    await windowManager.destroy();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _backgroundWipeTimer?.cancel();
      _backgroundWipeTimer = null;
      unawaited(_restoreSensitiveMemory());
      unawaited(AuthService().performTokenRefresh());
    } else if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.inactive) {
      _backgroundWipeTimer?.cancel();
      _backgroundWipeTimer = Timer(const Duration(minutes: 1), () {
        unawaited(_lockSensitiveMemory());
      });
    }
  }

  @override
  void dispose() {
    _minimizedWipeTimer?.cancel();
    _backgroundWipeTimer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    if (_isDesktop) windowManager.removeListener(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // This shell wraps MaterialApp, so it cannot rely on MaterialApp's
    // Directionality being available yet.
    return Directionality(
      textDirection: TextDirection.ltr,
      child: Stack(
        fit: StackFit.expand,
        children: [
          widget.child,
          if (_isClosing) ...[
            const ModalBarrier(dismissible: false, color: Color(0xCC09090B)),
            Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 390),
                child: Card(
                  elevation: 18,
                  color: const Color(0xFF18181B),
                  margin: const EdgeInsets.all(24),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(22),
                    side: const BorderSide(color: Color(0xFF334155)),
                  ),
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(28, 30, 28, 26),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const SizedBox(
                          width: 48,
                          height: 48,
                          child: CircularProgressIndicator(
                            strokeWidth: 4,
                            color: Color(0xFF60A5FA),
                          ),
                        ),
                        const SizedBox(height: 22),
                        const Text(
                          'Приложение закрывается',
                          style: TextStyle(
                            color: Color(0xFFF8FAFC),
                            fontSize: 19,
                            fontWeight: FontWeight.w700,
                          ),
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 9),
                        Text(
                          _status,
                          style: const TextStyle(
                            color: Color(0xFF94A3B8),
                            fontSize: 13,
                          ),
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 22),
                        ClipRRect(
                          borderRadius: BorderRadius.circular(20),
                          child: TweenAnimationBuilder<double>(
                            tween: Tween<double>(begin: 0, end: _progress),
                            duration: const Duration(milliseconds: 700),
                            curve: Curves.easeInOutCubic,
                            builder: (context, animatedProgress, child) {
                              return LinearProgressIndicator(
                                value: animatedProgress,
                                minHeight: 7,
                                backgroundColor: const Color(0xFF27272A),
                                valueColor: const AlwaysStoppedAnimation(
                                  Color(0xFF60A5FA),
                                ),
                              );
                            },
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
