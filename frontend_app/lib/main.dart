import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:webauthn_secure_storage/webauthn_secure_storage.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'services/auth_service.dart';
import 'rust/frb_generated.dart';
import 'rust/api/clients/auth_client.dart';
import 'rust/api/clients/account_client.dart';
import 'rust/api/types/master_key.dart';
import 'rust/api/types/security.dart';

import 'home_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await RustLib.init();

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RustPass Manager',
      debugShowCheckedModeBanner: false,
      builder: (context, child) {
        return MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: TextScaler.noScaling),
          child: child!,
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

  String baseUrl = 'http://localhost:8080';

  @override
  void dispose() {
    _loginController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _showDebugConfigDialog() async {
    final TextEditingController urlController = TextEditingController(
      text: baseUrl,
    );

    await showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          backgroundColor: const Color(0xFF18181B),
          title: const Text(
            '⚙️ Настройка Debug Server',
            style: TextStyle(fontSize: 16),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Введите актуальный IP и порт бэкенда для локальной сети:',
                style: TextStyle(fontSize: 13, color: Color(0xFFA1A1AA)),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: urlController,
                style: const TextStyle(color: Colors.white, fontSize: 14),
                decoration: _inputDecoration(
                  'Base URL (например, http://192.168.1.15:8080)',
                ),
              ),
            ],
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
                setState(() {
                  baseUrl = urlController.text.trim();
                });
                Navigator.pop(context);
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('⚠️ Base URL изменен на: $baseUrl'),
                    backgroundColor: const Color(0xFF10B981),
                  ),
                );
              },
              child: const Text('Сохранить'),
            ),
          ],
        );
      },
    );
  }

  Future<void> _submitForm() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
    });

    try {
      if (isLogin) {
        await _loginToServer();
      } else {
        await _registerToServer();
      }
    } catch (e) {
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
        });
      }
    }
  }

  // 🔑 Вход по Passkey через LoginWithPasskeyClient
  Future<void> _loginWithPasskey() async {
    final username = _loginController.text.trim();
    if (username.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('⚠️ Сначала введите логин для входа по Passkey'),
          backgroundColor: Color(0xFFEF4444),
        ),
      );
      return;
    }

    setState(() {
      _isLoading = true;
    });

    try {
      final client = await LoginWithPasskeyClient.withBaseUrl(baseUrl: baseUrl);
      final PasskeyChallenge challenge = await client.step1(username: username);

      final requestOptions = PublicKeyCredentialRequestOptionsJson.fromJson(
        jsonDecode(challenge.passkeyPropsJson),
      );

      final biometricStorage = BiometricStorage();
      final assertion = await biometricStorage.authenticateWithPasskey(
        requestOptions,
      );

      final String passkeyResultJson = jsonEncode(assertion.toJson());

      final tokens = await client.step2(
        operationId: challenge.operationId,
        passkeyAssertionJson: passkeyResultJson,
      );

      final accountClient = await AccountClient.withBaseUrl(baseUrl: baseUrl);
      final accountInfo = await accountClient.getInfo(accessToken: tokens.$1);

      AuthService().saveTokens(tokens.$1, tokens.$2, currentBaseUrl: baseUrl);

      if (mounted) {
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
              accessToken: tokens.$1,
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('❌ Ошибка Passkey входа: $e'),
            backgroundColor: const Color(0xFFEF4444),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
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

    final userPassword = await UserPassword.newInstance(password: password);
    final cryptoKey = await CryptoKey.fromUserPassword(
      userPassword: userPassword,
      username: username,
    );

    try {
      final client = await LoginWithPasstotpClient.withBaseUrl(
        baseUrl: baseUrl,
      );

      // Шаг 1: Получаем flow
      final flow = await client.step1(username: username, cryptoKey: cryptoKey);

      // Запрос TOTP кода у пользователя
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

      final accountClient = await AccountClient.withBaseUrl(baseUrl: baseUrl);
      final accountInfo = await accountClient.getInfo(accessToken: tokens.$1);

      AuthService().saveTokens(tokens.$1, tokens.$2, currentBaseUrl: baseUrl);

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

    final userPassword = await UserPassword.newInstance(password: password);
    final cryptoKey = await CryptoKey.fromUserPassword(
      userPassword: userPassword,
      username: username,
    );

    try {
      final client = await RegistrationWithPasstotpClient.withBaseUrl(
        baseUrl: baseUrl,
      );

      // Шаг 1 регистрации
      final flow = await client.step1(username: username, cryptoKey: cryptoKey);

      final String totpSettings = await flow.totpUrl();

      // Настройка TOTP (сканирование QR-кода)
      final totpCode = await _showTotpSetupDialog(context, totpSettings);
      if (totpCode == null || totpCode.isEmpty) {
        await cryptoKey.zeroize();
        return;
      }

      // Шаг 2 регистрации с проверочным кодом
      final tokens = await client.step2(flow: flow, totpCode: totpCode);

      final accountClient = await AccountClient.withBaseUrl(baseUrl: baseUrl);
      final accountInfo = await accountClient.getInfo(accessToken: tokens.$1);

      AuthService().saveTokens(tokens.$1, tokens.$2, currentBaseUrl: baseUrl);

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

  Future<String?> _showTotpSetupDialog(
    BuildContext context,
    String totpUri,
  ) async {
    final TextEditingController codeController = TextEditingController();
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        return Dialog(
          backgroundColor: const Color(0xFF18181B),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
          child: SizedBox(
            width: 360,
            child: Padding(
              padding: const EdgeInsets.all(24),
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
                      style: TextStyle(fontSize: 13, color: Color(0xFFA1A1AA)),
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
                          width: 180,
                          height: 180,
                          child: QrImageView(
                            data: totpUri,
                            version: QrVersions.auto,
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: codeController,
                      keyboardType: TextInputType.number,
                      maxLength: 8,
                      onSubmitted: (value) {
                        final code = value.trim();
                        if (code.length == 6 || code.length == 8) {
                          Navigator.pop(context, code);
                        }
                      },
                      style: const TextStyle(color: Colors.white),
                      decoration: _inputDecoration(
                        'Введите 6 или 8-значный код',
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
                            if (code.length == 6 || code.length == 8) {
                              Navigator.pop(context, code);
                            } else {
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(
                                  content: Text(
                                    '⚠️ Код должен содержать 6 или 8 символов',
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
            maxLength: 8,
            autofocus: true,
            onSubmitted: (value) {
              final code = value.trim();
              if (code.length == 6 || code.length == 8) {
                Navigator.pop(context, code);
              }
            },
            style: const TextStyle(color: Colors.white),
            decoration: _inputDecoration('Введите 6 или 8-значный код'),
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
                if (code.length == 6 || code.length == 8) {
                  Navigator.pop(context, code);
                } else {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('⚠️ Код должен содержать 6 или 8 символов'),
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
                width: 380,
                padding: const EdgeInsets.all(32),
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
                      if (isLogin) ...[
                        OutlinedButton.icon(
                          onPressed: _isLoading ? null : _loginWithPasskey,
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
                        const SizedBox(height: 14),
                        const Center(
                          child: Text(
                            'или с паролем',
                            style: TextStyle(
                              color: Color(0xFF71717A),
                              fontSize: 12,
                            ),
                          ),
                        ),
                        const SizedBox(height: 14),
                      ],
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
                    ],
                  ),
                ),
              ),
            ),
          ),

          if (kDebugMode)
            Positioned(
              bottom: 16,
              left: 16,
              child: FloatingActionButton.extended(
                onPressed: _showDebugConfigDialog,
                backgroundColor: const Color(0xFF18181B),
                foregroundColor: const Color(0xFFA1A1AA),
                elevation: 2,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8),
                  side: const BorderSide(color: Color(0xFF27272A)),
                ),
                icon: const Icon(
                  Icons.bug_report,
                  size: 16,
                  color: Color(0xFF10B981),
                ),
                label: Text(
                  'API: $baseUrl',
                  style: const TextStyle(fontSize: 12),
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
