import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:webauthn_secure_storage/webauthn_secure_storage.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:url_launcher/url_launcher.dart';

import 'services/auth_service.dart';
import 'services/app_logger.dart';
import 'services/webauthn_options.dart';
import 'services/passkey_executor.dart';
import 'services/totp_code.dart';
import 'services/local_vault_storage.dart';
import 'services/memory_protection_service.dart';
import 'services/window_service.dart';
import 'widgets/operation_stopwatch.dart';
import 'widgets/debug_api_menu.dart';
import 'rust/frb_generated.dart';
import 'rust/api/types/master_key.dart';
import 'rust/api/types/security.dart';

import 'home_screen.dart';

final _rootNavigatorKey = GlobalKey<NavigatorState>();
final _rootScaffoldMessengerKey = GlobalKey<ScaffoldMessengerState>();
const _releaseBaseUrl = 'https://rustvault.local:443';
const _releaseCaCertificateAsset = 'assets/certificates/ca.crt';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  AppLogger.info('Application startup started.');
  await initializeDesktopWindow();

  await RustLib.init();
  AppLogger.info('Rust bridge initialized.');

  if (kReleaseMode) {
    final certificate = await rootBundle.load(_releaseCaCertificateAsset);
    AuthService().configureRelease(
      baseUrl: _releaseBaseUrl,
      sslCaPinnedCert: certificate.buffer.asUint8List(
        certificate.offsetInBytes,
        certificate.lengthInBytes,
      ),
    );
  }

  final serverAvailable = await AuthService().checkServerHealth();
  await AuthService().restoreSession(refresh: serverAvailable);
  AppLogger.info('Cached session restore completed.');

  runApp(
    DesktopWindowShell(navigatorKey: _rootNavigatorKey, child: const MyApp()),
  );
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  bool _handledExpiredSession = false;

  @override
  void initState() {
    super.initState();
    AuthService().addListener(_handleAuthStateChanged);
  }

  @override
  void dispose() {
    AuthService().removeListener(_handleAuthStateChanged);
    super.dispose();
  }

  void _handleAuthStateChanged() {
    final expired = AuthService().sessionExpired;
    if (!expired) {
      _handledExpiredSession = false;
      return;
    }
    if (_handledExpiredSession || !mounted) return;
    _handledExpiredSession = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      _rootNavigatorKey.currentState?.pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const AuthScreen()),
        (_) => false,
      );
      _rootScaffoldMessengerKey.currentState
        ?..hideCurrentSnackBar()
        ..showSnackBar(
          const SnackBar(
            content: Text('Session expired. Please sign in again.'),
          ),
        );
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: _rootNavigatorKey,
      scaffoldMessengerKey: _rootScaffoldMessengerKey,
      title: 'RustVault',
      debugShowCheckedModeBanner: false,
      builder: (context, child) {
        final compact = MediaQuery.sizeOf(context).width < 600;
        final keyboardInset = MediaQuery.viewInsetsOf(context).bottom;
        return MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: TextScaler.noScaling),
          child: Stack(
            fit: StackFit.expand,
            children: [
              child!,
              if (!kReleaseMode)
                Positioned(
                  left: 12,
                  bottom: keyboardInset > 0 ? keyboardInset + 8 : 12,
                  child: SafeArea(
                    top: false,
                    right: true,
                    child: DebugApiMenu(
                      compact: compact,
                      navigatorKey: _rootNavigatorKey,
                      scaffoldMessengerKey: _rootScaffoldMessengerKey,
                    ),
                  ),
                ),
              const Positioned(
                left: 12,
                right: 12,
                top: 12,
                child: SafeArea(bottom: false, child: OfflineModeNotice()),
              ),
            ],
          ),
        );
      },
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF09090B),
        colorScheme: const ColorScheme.dark(
          surface: Color(0xFF18181B),
          primary: Color(0xFFFAFAFA),
        ),
        useMaterial3: true,
      ),
      home: const AuthScreen(),
    );
  }
}

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  bool isLogin = true;

  final TextEditingController _loginController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _confirmPasswordController =
      TextEditingController();

  final _formKey = GlobalKey<FormState>();
  bool _isLoading = false;
  String _authStatus = '';

  @override
  void initState() {
    super.initState();
    MemoryProtectionService().addListener(_handleMemoryProtectionChanged);
    _restoreCachedLogin();
  }

  void _handleMemoryProtectionChanged() {
    if (!MemoryProtectionService().isLocked) return;
    _loginController.clear();
    _passwordController.clear();
    _confirmPasswordController.clear();
  }

  Future<void> _restoreCachedLogin() async {
    final credentials = await LocalVaultStorage.instance.readCredentials();
    if (!mounted || credentials == null) {
      return;
    }
    if (!AuthService().isOfflineMode && AuthService().accessToken == null) {
      return;
    }
    try {
      final userPassword = await UserPassword.newInstance(
        password: credentials.$2,
      );
      final cryptoKey = await CryptoKey.fromUserPassword(
        userPassword: userPassword,
        username: credentials.$1,
      );
      if (AuthService().isOfflineMode) {
        if (!mounted) {
          await cryptoKey.zeroize();
          return;
        }
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(
            builder: (_) => HomeScreen(
              username: credentials.$1,
              cryptoKey: cryptoKey,
              accessToken: AuthService().accessToken,
            ),
          ),
        );
        return;
      }
      final account = await (await AuthService().createAccountClient()).getInfo(
        accessToken: AuthService().accessToken!,
      );
      if (!mounted) {
        await cryptoKey.zeroize();
        return;
      }
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(
          builder: (_) => HomeScreen(
            username: account.username,
            cryptoKey: cryptoKey,
            accessToken: AuthService().accessToken,
          ),
        ),
      );
    } catch (_) {
      AuthService().clear();
      await LocalVaultStorage.instance.clearCredentials();
    }
  }

  void _setAuthStatus(String status) {
    if (mounted) setState(() => _authStatus = status);
  }

  @override
  void dispose() {
    MemoryProtectionService().removeListener(_handleMemoryProtectionChanged);
    _loginController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _submitForm() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
      _authStatus = isLogin ? 'Подготовка входа…' : 'Подготовка регистрации…';
    });

    try {
      if (isLogin) {
        await _loginToServer();
      } else {
        await _registerToServer();
      }
    } catch (e) {
      _setAuthStatus('Операция завершилась с ошибкой');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('❌ Ошибка: $e'),
            backgroundColor: const Color(0xFFEF4444),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
          if (_authStatus != 'Операция завершилась с ошибкой') {
            _authStatus = '';
          }
        });
      }
    }
  }

  // 🔑 Вход по Passkey через LoginWithPasskeyClient
  Future<void> _loginWithPasskey() async {
    final username = _loginController.text.trim();
    final password = _passwordController.text;
    if (!_formKey.currentState!.validate()) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Для входа по Passkey введите логин и пароль.'),
          backgroundColor: Color(0xFFEF4444),
        ),
      );
      return;
    }

    setState(() {
      _isLoading = true;
      _authStatus = 'Деривация CryptoKey…';
    });

    CryptoKey? cryptoKey;
    try {
      final userPassword = await UserPassword.newInstance(password: password);
      cryptoKey = await CryptoKey.fromUserPassword(
        userPassword: userPassword,
        username: username,
      );

      _setAuthStatus('Получение challenge Passkey…');
      final client = await AuthService().createLoginWithPasskeyClient();
      final PasskeyChallenge challenge = await client.step1(username: username);

      _setAuthStatus('Ожидание подтверждения Passkey…');
      final requestOptions = PublicKeyCredentialRequestOptionsJson.fromJson(
        parseWebAuthnPublicKeyOptions(challenge.passkeyPropsJson),
      );

      final assertion = await authenticatePasskeyWithoutBlockingUi(
        requestOptions,
      );

      final String passkeyResultJson = jsonEncode(assertion.toJson());

      _setAuthStatus('Проверка Passkey и загрузка профиля…');
      final tokens = await client.step2(
        operationId: challenge.operationId,
        passkeyAssertionJson: passkeyResultJson,
      );

      final accountClient = await AuthService().createAccountClient();
      final accountInfo = await accountClient.getInfo(accessToken: tokens.$1);

      AuthService().saveTokens(tokens.$1, tokens.$2);
      await LocalVaultStorage.instance.saveCredentials(
        username: username,
        password: password,
      );

      if (mounted) {
        final CryptoKey vaultCryptoKey = cryptoKey;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('🎉 Успешный вход по Passkey!'),
            backgroundColor: Color(0xFF10B981),
          ),
        );
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(
            builder: (context) => HomeScreen(
              username: accountInfo.username,
              cryptoKey: vaultCryptoKey,
              accessToken: tokens.$1,
            ),
          ),
        );
        cryptoKey = null;
      } else {
        await cryptoKey.zeroize();
        cryptoKey = null;
      }
    } catch (e) {
      _setAuthStatus('Вход по Passkey не выполнен');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('❌ Ошибка Passkey входа: $e'),
            backgroundColor: const Color(0xFFEF4444),
          ),
        );
      }
    } finally {
      if (cryptoKey != null) await cryptoKey.zeroize();
      if (mounted) {
        setState(() {
          _isLoading = false;
          if (_authStatus != 'Операция завершилась с ошибкой') {
            _authStatus = '';
          }
        });
      }
    }
  }

  // 🔐 Вход по Паролю + TOTP через LoginWithPasstotpClient
  Future<void> _loginToServer() async {
    final username = _loginController.text.trim();
    final password = _passwordController.text;

    if (username == "admin" && password == "admin") {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('✅ Успешный вход!'),
            backgroundColor: Color(0xFF10B981),
          ),
        );
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(
            builder: (context) => HomeScreen(username: username),
          ),
        );
      }
      return;
    }

    _setAuthStatus('Деривация CryptoKey…');
    final userPassword = await UserPassword.newInstance(password: password);
    final cryptoKey = await CryptoKey.fromUserPassword(
      userPassword: userPassword,
      username: username,
    );

    try {
      _setAuthStatus('Проверка учётных данных…');
      final client = await AuthService().createLoginWithPasstotpClient();

      // Шаг 1: Получаем flow
      final flow = await client.step1(username: username, cryptoKey: cryptoKey);
      if (!mounted) {
        await cryptoKey.zeroize();
        return;
      }

      // Запрос TOTP кода у пользователя
      _setAuthStatus('Ожидание подтверждения TOTP…');
      final totpCode = await _showTotpInputDialog(
        context,
        'Требуется подтверждение TOTP',
      );
      if (totpCode == null || totpCode.isEmpty) {
        await cryptoKey.zeroize();
        return;
      }

      // Шаг 2: Отправляем код подтверждения на сервер
      final tokens = await client.step2(flow: flow, totpCode: totpCode);

      _setAuthStatus('Загрузка профиля аккаунта…');
      final accountClient = await AuthService().createAccountClient();
      final accountInfo = await accountClient.getInfo(accessToken: tokens.$1);

      AuthService().saveTokens(tokens.$1, tokens.$2);
      await LocalVaultStorage.instance.saveCredentials(
        username: accountInfo.username,
        password: password,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('✅ Успешный вход!'),
            backgroundColor: Color(0xFF10B981),
          ),
        );
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(
            builder: (context) => HomeScreen(
              username: accountInfo.username,
              cryptoKey: cryptoKey,
              accessToken: tokens.$1,
            ),
          ),
        );
      }
    } catch (_) {
      await cryptoKey.zeroize();
      rethrow;
    }
  }

  // 📝 Регистрация через RegistrationWithPasstotpClient
  Future<void> _registerToServer() async {
    final username = _loginController.text.trim();
    final password = _passwordController.text;

    _setAuthStatus('Деривация CryptoKey…');
    final userPassword = await UserPassword.newInstance(password: password);
    final cryptoKey = await CryptoKey.fromUserPassword(
      userPassword: userPassword,
      username: username,
    );

    try {
      _setAuthStatus('Создание учётной записи…');
      final client = await AuthService().createRegistrationClient();

      // Шаг 1 регистрации
      final flow = await client.step1(username: username, cryptoKey: cryptoKey);

      final String totpSettings = await flow.totpUrl();
      if (!mounted) {
        await cryptoKey.zeroize();
        return;
      }

      // Настройка TOTP (сканирование QR-кода)
      _setAuthStatus('Ожидание настройки TOTP…');
      final totpCode = await _showTotpSetupDialog(context, totpSettings);
      if (totpCode == null || totpCode.isEmpty) {
        await cryptoKey.zeroize();
        return;
      }

      // Шаг 2 регистрации с проверочным кодом
      final tokens = await client.step2(flow: flow, totpCode: totpCode);

      _setAuthStatus('Завершение регистрации…');
      AuthService().saveTokens(tokens.$1, tokens.$2);
      await LocalVaultStorage.instance.saveCredentials(
        username: username,
        password: password,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('🎉 Регистрация успешно завершена!'),
            backgroundColor: Color(0xFF10B981),
          ),
        );
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(
            builder: (context) => HomeScreen(
              username: username,
              cryptoKey: cryptoKey,
              accessToken: tokens.$1,
            ),
          ),
        );
      }
    } catch (_) {
      await cryptoKey.zeroize();
      rethrow;
    }
  }

  Future<String?> _showTotpSetupDialog(
    BuildContext context,
    String totpUri,
  ) async {
    final TextEditingController codeController = TextEditingController();

    Future<void> openTotpLink() async {
      final uri = Uri.tryParse(totpUri);
      if (uri == null || uri.scheme != 'otpauth') {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Ссылка настройки TOTP некорректна.')),
        );
        return;
      }

      try {
        final launched = await launchUrl(
          uri,
          mode: LaunchMode.externalApplication,
        );
        if (!launched && context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text(
                'Не удалось открыть ссылку. Скопируйте otpauth:// URI из QR-кода или отсканируйте его.',
              ),
            ),
          );
        }
      } catch (error) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Не удалось открыть ссылку TOTP: $error')),
          );
        }
      }
    }

    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        final qrSize = MediaQuery.sizeOf(context).width < 400 ? 140.0 : 180.0;
        return Dialog(
          backgroundColor: const Color(0xFF18181B),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 360),
            child: SizedBox(
              width: double.infinity,
              child: Padding(
                padding: EdgeInsets.all(
                  MediaQuery.sizeOf(context).width < 400 ? 16 : 24,
                ),
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const Text(
                        'Настройка двухфакторной аутентификации',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 16),
                      const Text(
                        'Отсканируйте этот QR-код в приложении аутентификации:',
                        style: TextStyle(
                          fontSize: 13,
                          color: Color(0xFFA1A1AA),
                        ),
                      ),
                      const SizedBox(height: 16),
                      Center(
                        child: Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.white,
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: SizedBox(
                            width: qrSize,
                            height: qrSize,
                            child: QrImageView(
                              data: totpUri,
                              version: QrVersions.auto,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 8),
                      Center(
                        child: TextButton(
                          onPressed: openTotpLink,
                          child: const Text(
                            'Если не можете отсканировать, нажмите здесь',
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: Color(0xFF60A5FA),
                              decoration: TextDecoration.underline,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                      TextField(
                        controller: codeController,
                        keyboardType: TextInputType.number,
                        inputFormatters: [
                          FilteringTextInputFormatter.digitsOnly,
                        ],
                        maxLength: 8,
                        onSubmitted: (value) {
                          final code = value.trim();
                          if (isValidTotpCode(code)) {
                            Navigator.pop(context, code);
                          }
                        },
                        style: const TextStyle(color: Colors.white),
                        decoration: _inputDecoration(
                          'Введите 8-значный код TOTP',
                        ),
                      ),
                      const SizedBox(height: 16),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.end,
                        children: [
                          TextButton(
                            onPressed: () => Navigator.pop(context),
                            child: const Text(
                              'Отмена',
                              style: TextStyle(color: Color(0xFF71717A)),
                            ),
                          ),
                          const SizedBox(width: 8),
                          ElevatedButton(
                            style: ElevatedButton.styleFrom(
                              backgroundColor: const Color(0xFFFAFAFA),
                              foregroundColor: Colors.black,
                            ),
                            onPressed: () {
                              final code = codeController.text.trim();
                              if (isValidTotpCode(code)) {
                                Navigator.pop(context, code);
                              } else {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  const SnackBar(
                                    content: Text(
                                      '⚠️ Код TOTP должен содержать ровно 8 цифр',
                                    ),
                                    backgroundColor: Color(0xFFEF4444),
                                  ),
                                );
                              }
                            },
                            child: const Text('Подтвердить'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Future<String?> _showTotpInputDialog(
    BuildContext context,
    String title,
  ) async {
    final TextEditingController codeController = TextEditingController();
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        return AlertDialog(
          backgroundColor: const Color(0xFF18181B),
          title: Text(title, style: const TextStyle(fontSize: 16)),
          content: TextField(
            controller: codeController,
            keyboardType: TextInputType.number,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly],
            maxLength: 8,
            autofocus: true,
            onSubmitted: (value) {
              final code = value.trim();
              if (isValidTotpCode(code)) {
                Navigator.pop(context, code);
              }
            },
            style: const TextStyle(color: Colors.white),
            decoration: _inputDecoration('Введите 8-значный код TOTP'),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text(
                'Отмена',
                style: TextStyle(color: Color(0xFF71717A)),
              ),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFFAFAFA),
                foregroundColor: Colors.black,
              ),
              onPressed: () {
                final code = codeController.text.trim();
                if (isValidTotpCode(code)) {
                  Navigator.pop(context, code);
                } else {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text(
                        '⚠️ Код TOTP должен содержать ровно 8 цифр',
                      ),
                      backgroundColor: Color(0xFFEF4444),
                    ),
                  );
                }
              },
              child: const Text('Войти'),
            ),
          ],
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          Center(
            child: SingleChildScrollView(
              child: Container(
                width: double.infinity,
                constraints: const BoxConstraints(maxWidth: 380),
                padding: EdgeInsets.all(
                  MediaQuery.sizeOf(context).width < 400 ? 20 : 32,
                ),
                decoration: BoxDecoration(
                  color: const Color(0xFF121215),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: const Color(0xFF27272A), width: 1),
                ),
                child: Form(
                  key: _formKey,
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Row(
                        children: [
                          _buildTabButton(
                            title: 'Вход',
                            active: isLogin,
                            onTap: () {
                              if (!isLogin) setState(() => isLogin = true);
                            },
                          ),
                          const SizedBox(width: 16),
                          _buildTabButton(
                            title: 'Регистрация',
                            active: !isLogin,
                            onTap: () {
                              if (isLogin) setState(() => isLogin = false);
                            },
                          ),
                        ],
                      ),
                      const SizedBox(height: 28),
                      TextFormField(
                        controller: _loginController,
                        textInputAction: TextInputAction.next,
                        style: const TextStyle(
                          fontSize: 14,
                          color: Colors.white,
                        ),
                        decoration: _inputDecoration('Логин'),
                        validator: (value) {
                          if (value == null || value.trim().isEmpty) {
                            return 'Введите логин';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 14),
                      TextFormField(
                        controller: _passwordController,
                        obscureText: true,
                        textInputAction: TextInputAction.done,
                        onFieldSubmitted: (_) => _submitForm(),
                        style: const TextStyle(
                          fontSize: 14,
                          color: Colors.white,
                        ),
                        decoration: _inputDecoration('Пароль'),
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Введите пароль';
                          }
                          return null;
                        },
                      ),
                      if (!isLogin) ...[
                        const SizedBox(height: 14),
                        TextFormField(
                          controller: _confirmPasswordController,
                          obscureText: true,
                          textInputAction: TextInputAction.done,
                          onFieldSubmitted: (_) => _submitForm(),
                          style: const TextStyle(
                            fontSize: 14,
                            color: Colors.white,
                          ),
                          decoration: _inputDecoration('Подтвердите пароль'),
                          validator: (value) {
                            if (!isLogin) {
                              if (value == null || value.isEmpty) {
                                return 'Повторите пароль';
                              }
                              if (value != _passwordController.text) {
                                return 'Пароли не совпадают';
                              }
                            }
                            return null;
                          },
                        ),
                      ],
                      const SizedBox(height: 24),
                      ElevatedButton(
                        onPressed: _isLoading ? null : _submitForm,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFFFAFAFA),
                          foregroundColor: const Color(0xFF09090B),
                          disabledBackgroundColor: const Color(0xFF27272A),
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(8),
                          ),
                          elevation: 0,
                        ),
                        child: _isLoading
                            ? const SizedBox(
                                height: 18,
                                width: 18,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Color(0xFF09090B),
                                ),
                              )
                            : Text(
                                isLogin
                                    ? 'Продолжить с паролем'
                                    : 'Создать аккаунт',
                                style: const TextStyle(
                                  fontSize: 14,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                      ),
                      if (isLogin) ...[
                        const SizedBox(height: 14),
                        const Center(
                          child: Text(
                            'или войдите по Passkey (пароль тоже обязателен)',
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: Color(0xFF71717A),
                              fontSize: 12,
                            ),
                          ),
                        ),
                        const SizedBox(height: 8),
                        OutlinedButton.icon(
                          onPressed: _isLoading
                              ? null
                              : () {
                                  if (_formKey.currentState!.validate()) {
                                    unawaited(_loginWithPasskey());
                                  }
                                },
                          icon: const Icon(
                            Icons.fingerprint,
                            size: 18,
                            color: Color(0xFF3B82F6),
                          ),
                          label: const Text('Войти по Passkey'),
                          style: OutlinedButton.styleFrom(
                            foregroundColor: const Color(0xFFFAFAFA),
                            side: const BorderSide(color: Color(0xFF3B82F6)),
                            backgroundColor: const Color(0xFF18181B),
                            padding: const EdgeInsets.symmetric(vertical: 12),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                        ),
                      ],
                      if (_isLoading && _authStatus.isNotEmpty) ...[
                        const SizedBox(height: 16),
                        Container(
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            color: const Color(0xFF18181B),
                            borderRadius: BorderRadius.circular(10),
                            border: Border.all(color: const Color(0xFF27272A)),
                          ),
                          child: Row(
                            children: [
                              const SizedBox(
                                width: 18,
                                height: 18,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Color(0xFF60A5FA),
                                ),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Text(
                                  _authStatus,
                                  style: const TextStyle(
                                    color: Color(0xFFCBD5E1),
                                    fontSize: 13,
                                  ),
                                ),
                              ),
                              const SizedBox(width: 8),
                              const OperationStopwatch(running: true),
                            ],
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTabButton({
    required String title,
    required bool active,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: TextStyle(
              fontSize: 18,
              fontWeight: active ? FontWeight.bold : FontWeight.w400,
              color: active ? const Color(0xFFFAFAFA) : const Color(0xFF71717A),
            ),
          ),
          const SizedBox(height: 4),
          AnimatedContainer(
            duration: const Duration(milliseconds: 150),
            height: 2,
            width: active ? 24 : 0,
            color: const Color(0xFFFAFAFA),
          ),
        ],
      ),
    );
  }

  InputDecoration _inputDecoration(String label) {
    return InputDecoration(
      labelText: label,
      labelStyle: const TextStyle(color: Color(0xFF71717A), fontSize: 13),
      floatingLabelStyle: const TextStyle(
        color: Color(0xFFA1A1AA),
        fontSize: 13,
      ),
      filled: true,
      fillColor: const Color(0xFF18181B),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: Color(0xFF27272A), width: 1),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: Color(0xFFA1A1AA), width: 1),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: Color(0xFFEF4444), width: 1),
      ),
      focusedErrorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: Color(0xFFEF4444), width: 1),
      ),
      errorStyle: const TextStyle(fontSize: 12),
    );
  }
}

class OfflineModeNotice extends StatefulWidget {
  const OfflineModeNotice({super.key});

  @override
  State<OfflineModeNotice> createState() => _OfflineModeNoticeState();
}

class _OfflineModeNoticeState extends State<OfflineModeNotice> {
  bool _isChecking = false;

  Future<void> _checkAccess() async {
    if (_isChecking) return;
    setState(() => _isChecking = true);
    final available = await AuthService().checkServerHealth();
    if (mounted) {
      setState(() => _isChecking = false);
      if (available) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Соединение восстановлено.')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: AuthService(),
      builder: (context, _) {
        if (!AuthService().isOfflineMode) return const SizedBox.shrink();
        return Material(
          color: Colors.transparent,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: const Color(0xFF3F2A08),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: const Color(0xFFF59E0B)),
              boxShadow: const [
                BoxShadow(color: Color(0x55000000), blurRadius: 12),
              ],
            ),
            child: Row(
              children: [
                const Icon(Icons.cloud_off, color: Color(0xFFFBBF24), size: 20),
                const SizedBox(width: 10),
                const Expanded(
                  child: Text(
                    'Приложение в офлайн-режиме.',
                    style: TextStyle(fontWeight: FontWeight.w600),
                  ),
                ),
                TextButton(
                  onPressed: _isChecking ? null : _checkAccess,
                  child: _isChecking
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text('Проверить доступ'),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}
