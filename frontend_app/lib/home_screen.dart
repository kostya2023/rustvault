import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'services/auth_service.dart';
import 'main.dart';
import 'rust/api/clients/vault_client.dart';
import 'rust/api/clients/crypto_client.dart';
import 'rust/api/types/master_key.dart';
import 'rust/api/types/blob.dart';
import 'rust/api/types/crypto.dart' as rust_crypto;
import 'rust/api/types/errors.dart';

class PasswordItem {
  String title;
  String login;
  String password;
  String userComment;

  PasswordItem({
    required this.title,
    required this.login,
    required this.password,
    this.userComment = '',
  });

  rust_crypto.Key toRustKey() => rust_crypto.Key(
    serviceName: title,
    password: password,
    username: login,
    userComment: userComment,
  );

  factory PasswordItem.fromRustKey(rust_crypto.Key key) => PasswordItem(
    title: key.serviceName,
    login: key.username,
    password: key.password,
    userComment: key.userComment,
  );
}

class HomeScreen extends StatefulWidget {
  final String username;
  final CryptoKey? cryptoKey;
  final String? accessToken;

  const HomeScreen({
    super.key,
    required this.username,
    this.cryptoKey,
    this.accessToken,
  });

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  List<PasswordItem> _passwords = [];
  bool _isLoadingVault = true;
  bool _isSavingVault = false;
  bool _isSyncing = false;

  /// Хранилище успешно скачано и расшифровано. Пока это false, сохранять
  /// нельзя — иначе можно затереть серверные данные пустым списком.
  bool _vaultReady = false;
  String? _vaultError;

  // Последняя известная версия блоба на сервере.
  // В FRB 2.13 PlatformInt64 на Dart-стороне является обычным int.
  int _currentVaultVersion = 0;

  late List<bool> _showPasswordList;
  bool _isLoggingOut = false;
  final ScrollController _scrollController = ScrollController();

  // Очередь сохранений: параллельные вызовы объединяются, а версия блоба
  // увеличивается строго последовательно.
  Future<void>? _saveChain;
  bool _saveQueued = false;

  @override
  void initState() {
    super.initState();
    _showPasswordList = [];
    _loadVaultFromBackend();
  }

  @override
  void dispose() {
    _scrollController.dispose();
    widget.cryptoKey?.zeroize();
    super.dispose();
  }

  void _updatePasswordListState() {
    _showPasswordList = List.generate(_passwords.length, (_) => false);
  }

  String? _resolveAccessToken() =>
      AuthService().accessToken ?? widget.accessToken;

  bool get _isDemoSession =>
      widget.cryptoKey == null && _resolveAccessToken() == null;

  void _showSnack(String message, {bool isError = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(
          content: Text(message),
          backgroundColor: isError
              ? const Color(0xFFEF4444)
              : const Color(0xFF10B981),
        ),
      );
  }

  String _describeError(Object error) {
    if (error is SdkError_Server) {
      switch (error.code) {
        case 'AUTH_TOKEN_INVALID':
          return 'сессия истекла, войдите в аккаунт заново';
        case 'VAULT_METADATA_NOT_FOUND':
          return 'хранилище на сервере ещё не создано';
        case 'BLOB_VERSION_NOT_INCREASING':
        case 'BLOB_VERSION_INVALID':
          return 'версия на сервере новее — нажмите «Синхронизировать с сервером»';
        case 'BLOB_TOO_LARGE':
        case 'PAYLOAD_TOO_LARGE':
          return 'хранилище слишком большое для загрузки';
        case 'PASSWORD_AUTHENTICATION_FAILED':
        case 'TOTP_INVALID':
          return 'сервер не подтвердил пароль или TOTP-код';
        default:
          return '${error.text} (код ${error.code}, trace ${error.traceId})';
      }
    }
    if (error is SdkError_Network) {
      return 'нет связи с сервером: ${error.field0}';
    }
    if (error is SdkError_Crypto) {
      return 'не удалось расшифровать данные: ${error.field0}';
    }
    if (error is SdkError_Internal) {
      return 'внутренняя ошибка SDK: ${error.field0}';
    }
    return error.toString();
  }

  bool _isMetadataMissing(Object error) =>
      error is SdkError_Server && error.code == 'VAULT_METADATA_NOT_FOUND';

  /// Выполняет запрос с access token и один раз повторяет его после
  /// автоматического обновления токена, если сервер вернул AUTH_TOKEN_INVALID.
  Future<T> _withTokenRetry<T>(
    Future<T> Function(String accessToken) action,
  ) async {
    var accessToken = _resolveAccessToken();
    if (accessToken == null) {
      throw StateError('Нет access token. Войдите в аккаунт ещё раз.');
    }

    try {
      return await action(accessToken);
    } on SdkError catch (error) {
      final isAuthError =
          error is SdkError_Server && error.code == 'AUTH_TOKEN_INVALID';
      if (!isAuthError) rethrow;

      final refreshed = await AuthService().performTokenRefresh();
      accessToken = AuthService().accessToken;
      if (!refreshed || accessToken == null) rethrow;

      return action(accessToken);
    }
  }

  // 📥 Загрузка и расшифровка хранилища с сервера.
  Future<void> _loadVaultFromBackend() async {
    await _fetchVault(showFeedback: false);
  }

  /// Принудительно забирает с сервера актуальные метаданные и блоб,
  /// расшифровывает их текущим ключом и заменяет локальный список.
  Future<void> _syncVaultFromServer() async {
    if (_isSyncing) return;

    if (widget.cryptoKey == null) {
      _showSnack(
        _isDemoSession
            ? 'Демо-вход admin/admin не подключён к серверу. Войдите реальным аккаунтом.'
            : 'Синхронизация недоступна при входе по Passkey: ключ расшифровки хранилища не сохраняется. Войдите по паролю.',
        isError: true,
      );
      return;
    }

    setState(() => _isSyncing = true);
    try {
      await _fetchVault(showFeedback: true, keepDataOnError: true);
    } finally {
      if (mounted) setState(() => _isSyncing = false);
    }
  }

  Future<bool> _fetchVault({
    required bool showFeedback,
    bool keepDataOnError = false,
  }) async {
    final cryptoKey = widget.cryptoKey;

    if (cryptoKey == null) {
      if (mounted) {
        setState(() {
          _isLoadingVault = false;
          _vaultReady = false;
          _vaultError = _isDemoSession
              ? 'Демо-вход admin/admin: серверное хранилище недоступно. Войдите реальным аккаунтом.'
              : 'Вход по Passkey: расшифровка хранилища пока недоступна. Войдите по паролю, чтобы увидеть пароли.';
        });
      }
      if (showFeedback) {
        _showSnack(
          _isDemoSession
              ? 'Демо-вход admin/admin не подключён к серверу.'
              : 'Для просмотра хранилища нужен вход по паролю.',
          isError: true,
        );
      }
      return false;
    }

    if (_resolveAccessToken() == null) {
      if (mounted) {
        setState(() {
          _isLoadingVault = false;
          _vaultReady = false;
          _vaultError = 'Сессия не найдена. Войдите в аккаунт заново.';
        });
      }
      if (showFeedback) {
        _showSnack('Сессия не найдена. Войдите заново.', isError: true);
      }
      return false;
    }

    if (mounted) {
      setState(() {
        _isLoadingVault = true;
        _vaultError = null;
      });
    }

    try {
      final baseUrl = AuthService().baseUrl;
      final vaultClient = await VaultClient.withBaseUrl(baseUrl: baseUrl);
      final cryptoClient = await CryptoClient.newInstance();

      // Получаем актуальную версию блоба на сервере.
      int storedVersion;
      try {
        final metadata = await _withTokenRetry(
          (accessToken) => vaultClient.getMetadata(accessToken: accessToken),
        );
        storedVersion = metadata.version;
      } catch (error) {
        if (!_isMetadataMissing(error)) rethrow;
        storedVersion = 0;
      }

      // Версия 0 — сервер только что создал пустое хранилище-заглушку.
      if (storedVersion == 0) {
        if (!mounted) return true;
        setState(() {
          _currentVaultVersion = 0;
          _passwords = [];
          _updatePasswordListState();
          _vaultReady = true;
          _vaultError = null;
          _isLoadingVault = false;
        });
        if (showFeedback) {
          _showSnack(
            'На сервере пока нет сохранённых паролей.',
            isError: false,
          );
        }
        return true;
      }

      final Blob blob = await _withTokenRetry(
        (accessToken) => vaultClient.download(accessToken: accessToken),
      );

      // decryptKeys возвращает Keys напрямую и не требует работы с TbsBlob.
      final rust_crypto.Keys keys = await cryptoClient.decryptKeys(
        cryptoKey: cryptoKey,
        blob: blob,
      );

      if (!mounted) return true;

      setState(() {
        _currentVaultVersion = storedVersion;
        _passwords = keys.keys
            .map((key) => PasswordItem.fromRustKey(key))
            .toList();
        _updatePasswordListState();
        _vaultReady = true;
        _vaultError = null;
        _isLoadingVault = false;
      });

      if (showFeedback) {
        _showSnack(
          'Хранилище синхронизировано: ${_passwords.length} записей.',
          isError: false,
        );
      }
      return true;
    } catch (error, stackTrace) {
      debugPrint('Ошибка загрузки/расшифровки хранилища: $error');
      debugPrintStack(stackTrace: stackTrace);

      if (!mounted) return false;

      setState(() {
        _vaultReady = false;
        _vaultError = _describeError(error);
        _isLoadingVault = false;
        if (!keepDataOnError) {
          _passwords = [];
          _updatePasswordListState();
        }
      });

      _showSnack(
        'Не удалось загрузить хранилище: ${_describeError(error)}',
        isError: true,
      );
      return false;
    }
  }

  // 📤 Шифрование и отправка хранилища на сервер.
  void _requestVaultSave() {
    if (_saveChain != null) {
      _saveQueued = true;
      return;
    }

    _saveChain = _runVaultSaveLoop().whenComplete(() {
      _saveChain = null;
    });
  }

  Future<void> _runVaultSaveLoop() async {
    do {
      _saveQueued = false;
      await _saveVaultToBackend();
      // Если во время сохранения список изменился — сохраняем ещё раз.
    } while (_saveQueued && mounted);
  }

  Future<void> _saveVaultToBackend() async {
    final cryptoKey = widget.cryptoKey;

    if (cryptoKey == null) {
      _showSnack('Нет криптографического ключа сессии.', isError: true);
      return;
    }

    if (!_vaultReady) {
      _showSnack(
        'Хранилище не загружено — сохранение отключено, чтобы не потерять данные. Нажмите «Синхронизировать с сервером».',
        isError: true,
      );
      return;
    }

    if (mounted) {
      setState(() => _isSavingVault = true);
    }

    try {
      final baseUrl = AuthService().baseUrl;
      final vaultClient = await VaultClient.withBaseUrl(baseUrl: baseUrl);
      final cryptoClient = await CryptoClient.newInstance();

      final rust_crypto.Keys keys = rust_crypto.Keys(
        keys: _passwords.map((item) => item.toRustKey()).toList(),
      );

      // encryptKeys сам формирует соль/нонс и тег внутри Rust.
      final Blob newBlob = await cryptoClient.encryptKeys(
        cryptoKey: cryptoKey,
        keys: keys,
      );

      // Сервер требует версию строго больше сохранённой.
      final savedVersion = await _uploadVaultWithRetry(vaultClient, newBlob);
      _currentVaultVersion = savedVersion;

      if (mounted) {
        _showSnack(
          'Сохранено на сервере (версия $savedVersion).',
          isError: false,
        );
      }
    } catch (error, stackTrace) {
      debugPrint('Ошибка сохранения хранилища: $error');
      debugPrintStack(stackTrace: stackTrace);

      if (mounted) {
        _showSnack(
          'Не удалось сохранить: ${_describeError(error)}',
          isError: true,
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isSavingVault = false);
      }
    }
  }

  Future<int> _uploadVaultWithRetry(VaultClient vaultClient, Blob blob) async {
    var version = _currentVaultVersion + 1;
    try {
      await _withTokenRetry(
        (accessToken) => vaultClient.upload(
          accessToken: accessToken,
          blob: blob,
          version: version,
        ),
      );
      return version;
    } on SdkError catch (error) {
      final staleVersion =
          error is SdkError_Server &&
          (error.code == 'BLOB_VERSION_NOT_INCREASING' ||
              error.code == 'BLOB_VERSION_INVALID');
      if (!staleVersion) rethrow;

      // Другое устройство уже сохранило более новую версию: подтягиваем
      // серверную версию и повторяем загрузку с версией +1.
      final metadata = await _withTokenRetry(
        (accessToken) => vaultClient.getMetadata(accessToken: accessToken),
      );
      _currentVaultVersion = metadata.version;
      version = metadata.version + 1;

      await _withTokenRetry(
        (accessToken) => vaultClient.upload(
          accessToken: accessToken,
          blob: blob,
          version: version,
        ),
      );
      return version;
    }
  }

  Future<void> _handleLogout() async {
    setState(() {
      _isLoggingOut = true;
    });

    try {
      await AuthService().logout();
      if (mounted) {
        Navigator.pushAndRemoveUntil(
          context,
          MaterialPageRoute(builder: (context) => const AuthScreen()),
          (route) => false,
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoggingOut = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('⚠️ Ошибка выхода: $e'),
            backgroundColor: const Color(0xFFEF4444),
          ),
        );
      }
    }
  }

  void _showAddPasswordDialog() {
    final titleController = TextEditingController();
    final loginController = TextEditingController();
    final passwordController = TextEditingController();
    final commentController = TextEditingController();

    showDialog(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          backgroundColor: const Color(0xFF14141A),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: const BorderSide(color: Color(0xFF2563EB), width: 1.5),
          ),
          title: const Text(
            '➕ Добавить новый пароль',
            style: TextStyle(
              color: Color(0xFFFAFAFA),
              fontSize: 18,
              fontWeight: FontWeight.bold,
            ),
          ),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: titleController,
                  style: const TextStyle(color: Colors.white),
                  decoration: _dialogInputDecoration('Название / Сайт'),
                ),
                const SizedBox(height: 14),
                TextField(
                  controller: loginController,
                  style: const TextStyle(color: Colors.white),
                  decoration: _dialogInputDecoration('Логин / Email'),
                ),
                const SizedBox(height: 14),
                TextField(
                  controller: passwordController,
                  style: const TextStyle(color: Colors.white),
                  decoration: _dialogInputDecoration('Пароль'),
                  obscureText: true,
                ),
                const SizedBox(height: 14),
                TextField(
                  controller: commentController,
                  style: const TextStyle(color: Colors.white),
                  decoration: _dialogInputDecoration(
                    'Комментарий (необязательно)',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: const Text(
                'Отмена',
                style: TextStyle(color: Color(0xFFA1A1AA)),
              ),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF2563EB),
                foregroundColor: Colors.white,
              ),
              onPressed: () {
                final title = titleController.text.trim();
                final pass = passwordController.text;

                if (title.isNotEmpty && pass.isNotEmpty) {
                  setState(() {
                    _passwords.add(
                      PasswordItem(
                        title: title,
                        login: loginController.text.trim(),
                        password: pass,
                        userComment: commentController.text.trim(),
                      ),
                    );
                    _updatePasswordListState();
                  });
                  Navigator.pop(dialogContext);
                  _requestVaultSave();
                }
              },
              child: const Text('Сохранить'),
            ),
          ],
        );
      },
    );
  }

  void _showEditPasswordDialog(int index) {
    final item = _passwords[index];
    final titleController = TextEditingController(text: item.title);
    final loginController = TextEditingController(text: item.login);
    final passwordController = TextEditingController(text: item.password);
    final commentController = TextEditingController(text: item.userComment);

    showDialog(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          backgroundColor: const Color(0xFF14141A),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: const BorderSide(color: Color(0xFF3B82F6), width: 1.5),
          ),
          title: const Text(
            '✏️ Редактировать запись',
            style: TextStyle(color: Color(0xFFFAFAFA), fontSize: 18),
          ),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: titleController,
                  style: const TextStyle(color: Colors.white),
                  decoration: _dialogInputDecoration('Название'),
                ),
                const SizedBox(height: 14),
                TextField(
                  controller: loginController,
                  style: const TextStyle(color: Colors.white),
                  decoration: _dialogInputDecoration('Логин'),
                ),
                const SizedBox(height: 14),
                TextField(
                  controller: passwordController,
                  style: const TextStyle(color: Colors.white),
                  decoration: _dialogInputDecoration('Пароль'),
                  obscureText: true,
                ),
                const SizedBox(height: 14),
                TextField(
                  controller: commentController,
                  style: const TextStyle(color: Colors.white),
                  decoration: _dialogInputDecoration(
                    'Комментарий (необязательно)',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: const Text(
                'Отмена',
                style: TextStyle(color: Color(0xFFA1A1AA)),
              ),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF2563EB),
                foregroundColor: Colors.white,
              ),
              onPressed: () {
                setState(() {
                  _passwords[index] = PasswordItem(
                    title: titleController.text.trim(),
                    login: loginController.text.trim(),
                    password: passwordController.text,
                    userComment: commentController.text.trim(),
                  );
                });
                Navigator.pop(dialogContext);
                _requestVaultSave();
              },
              child: const Text('Обновить'),
            ),
          ],
        );
      },
    );
  }

  void _showProfileDialog() {
    showDialog(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          backgroundColor: const Color(0xFF14141A),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: const BorderSide(color: Color(0xFF3B82F6), width: 1.5),
          ),
          title: const Row(
            children: [
              Icon(Icons.account_circle, color: Color(0xFF3B82F6)),
              SizedBox(width: 10),
              Text(
                '👤 Профиль аккаунта',
                style: TextStyle(color: Color(0xFFFAFAFA), fontSize: 18),
              ),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildProfileInfoRow('Имя пользователя:', widget.username),
              const SizedBox(height: 12),
              _buildProfileInfoRow(
                'Сохранено паролей:',
                '${_passwords.length} шт.',
              ),
              const SizedBox(height: 12),
              _buildProfileInfoRow(
                'Статус защиты:',
                '🔒 Защищено Zero-Knowledge',
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: const Text(
                'Закрыть',
                style: TextStyle(color: Color(0xFFA1A1AA)),
              ),
            ),
            ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFEF4444),
                foregroundColor: Colors.white,
              ),
              onPressed: _isLoggingOut
                  ? null
                  : () {
                      Navigator.pop(dialogContext);
                      _handleLogout();
                    },
              icon: const Icon(Icons.logout, size: 16),
              label: const Text('Выйти из аккаунта'),
            ),
          ],
        );
      },
    );
  }

  Widget _buildProfileInfoRow(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
        ),
        Text(
          value,
          style: const TextStyle(
            color: Color(0xFFFAFAFA),
            fontSize: 13,
            fontWeight: FontWeight.bold,
          ),
        ),
      ],
    );
  }

  Future<void> _deletePassword(int index) async {
    final item = _passwords[index];
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: const Color(0xFF14141A),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: Color(0xFFEF4444), width: 1.5),
        ),
        title: const Text(
          'Удалить запись?',
          style: TextStyle(color: Color(0xFFFAFAFA), fontSize: 18),
        ),
        content: Text(
          'Запись «${item.title}» будет удалена из хранилища на сервере.',
          style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text(
              'Отмена',
              style: TextStyle(color: Color(0xFFA1A1AA)),
            ),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFEF4444),
              foregroundColor: Colors.white,
            ),
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Удалить'),
          ),
        ],
      ),
    );

    if (confirmed != true || !mounted || index >= _passwords.length) return;

    setState(() {
      _passwords.removeAt(index);
      _updatePasswordListState();
    });
    _requestVaultSave();
  }

  InputDecoration _dialogInputDecoration(String label) {
    return InputDecoration(
      labelText: label,
      labelStyle: const TextStyle(color: Color(0xFF71717A), fontSize: 13),
      filled: true,
      fillColor: const Color(0xFF1C1C24),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: Color(0xFF27272A)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: Color(0xFF3B82F6)),
      ),
    );
  }

  Widget _buildEmptyVault() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.lock_open, size: 44, color: Color(0xFF334155)),
          const SizedBox(height: 10),
          const Text(
            'Список паролей пуст',
            style: TextStyle(color: Color(0xFF94A3B8), fontSize: 14),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 6),
          Text(
            'Версия на сервере: $_currentVaultVersion',
            style: const TextStyle(color: Color(0xFF64748B), fontSize: 12),
          ),
        ],
      ),
    );
  }

  Widget _buildVaultUnavailable() {
    final hasKey = widget.cryptoKey != null;

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              hasKey ? Icons.cloud_off : Icons.lock_outline,
              size: 44,
              color: const Color(0xFF334155),
            ),
            const SizedBox(height: 10),
            Text(
              _vaultError ?? 'Хранилище не загружено',
              style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 14),
              textAlign: TextAlign.center,
            ),
            if (hasKey) ...[
              const SizedBox(height: 16),
              ElevatedButton.icon(
                onPressed: _isSyncing ? null : _syncVaultFromServer,
                icon: const Icon(Icons.sync, size: 16),
                label: const Text('Синхронизировать с сервером'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF2563EB),
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF09090E),
      body: SafeArea(
        child: Column(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
              decoration: const BoxDecoration(
                color: Color(0xFF101016),
                border: Border(
                  bottom: BorderSide(color: Color(0xFF1E293B), width: 1),
                ),
              ),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: const Color(0xFF1E3A8A).withOpacity(0.4),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                        color: const Color(0xFF3B82F6),
                        width: 1.5,
                      ),
                    ),
                    child: const Icon(
                      Icons.shield_outlined,
                      color: Color(0xFF60A5FA),
                      size: 22,
                    ),
                  ),
                  const SizedBox(width: 12),
                  const Text(
                    'RustVault',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: Color(0xFFFAFAFA),
                    ),
                  ),
                  const Spacer(),
                  if (_isSavingVault) ...[
                    const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Color(0xFF3B82F6),
                      ),
                    ),
                    const SizedBox(width: 8),
                    const Text(
                      'Сохранение…',
                      style: TextStyle(fontSize: 12, color: Color(0xFF94A3B8)),
                    ),
                    const SizedBox(width: 12),
                  ],
                  GestureDetector(
                    onTap: _showProfileDialog,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 6,
                      ),
                      decoration: BoxDecoration(
                        color: const Color(0xFF14141E),
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(color: const Color(0xFF3B82F6)),
                      ),
                      child: Row(
                        children: [
                          const Icon(
                            Icons.person_outline,
                            size: 15,
                            color: Color(0xFF3B82F6),
                          ),
                          const SizedBox(width: 6),
                          Text(
                            widget.username,
                            style: const TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                              color: Color(0xFFFAFAFA),
                            ),
                          ),
                          const Icon(
                            Icons.arrow_drop_down,
                            size: 16,
                            color: Color(0xFF94A3B8),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
            Expanded(
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: 24,
                  vertical: 20,
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Text(
                          '🔐 Мои пароли',
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: Color(0xFFFAFAFA),
                          ),
                        ),
                        const Spacer(),
                        IconButton(
                          tooltip: 'Синхронизировать с сервером',
                          onPressed:
                              (_isSyncing ||
                                  _isLoadingVault ||
                                  widget.cryptoKey == null)
                              ? null
                              : _syncVaultFromServer,
                          icon: _isSyncing
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Color(0xFF3B82F6),
                                  ),
                                )
                              : const Icon(
                                  Icons.sync,
                                  size: 20,
                                  color: Color(0xFF3B82F6),
                                ),
                        ),
                        const SizedBox(width: 8),
                        ElevatedButton.icon(
                          onPressed:
                              (widget.cryptoKey == null ||
                                  !_vaultReady ||
                                  _isLoadingVault)
                              ? null
                              : _showAddPasswordDialog,
                          icon: const Icon(Icons.add, size: 16),
                          label: const Text('Добавить пароль'),
                          style: ElevatedButton.styleFrom(
                            backgroundColor: const Color(0xFF2563EB),
                            foregroundColor: Colors.white,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    Expanded(
                      child: _isLoadingVault && !_vaultReady
                          ? const Center(
                              child: CircularProgressIndicator(
                                color: Color(0xFF3B82F6),
                              ),
                            )
                          : !_vaultReady
                          ? _buildVaultUnavailable()
                          : _passwords.isEmpty
                          ? _buildEmptyVault()
                          : Scrollbar(
                              controller: _scrollController,
                              thumbVisibility: true,
                              child: ListView.separated(
                                controller: _scrollController,
                                itemCount: _passwords.length,
                                separatorBuilder: (context, index) =>
                                    const SizedBox(height: 8),
                                itemBuilder: (context, index) {
                                  final item = _passwords[index];
                                  final isVisible = _showPasswordList[index];

                                  return GestureDetector(
                                    onTap: () => _showEditPasswordDialog(index),
                                    child: Container(
                                      padding: const EdgeInsets.symmetric(
                                        horizontal: 14,
                                        vertical: 10,
                                      ),
                                      decoration: BoxDecoration(
                                        color: const Color(0xFF121218),
                                        borderRadius: BorderRadius.circular(10),
                                        border: Border.all(
                                          color: const Color(0xFF1E293B),
                                        ),
                                      ),
                                      child: Row(
                                        children: [
                                          Expanded(
                                            flex: 2,
                                            child: Column(
                                              crossAxisAlignment:
                                                  CrossAxisAlignment.start,
                                              children: [
                                                Text(
                                                  item.title,
                                                  style: const TextStyle(
                                                    fontWeight: FontWeight.bold,
                                                    color: Color(0xFFFAFAFA),
                                                  ),
                                                ),
                                                const SizedBox(height: 2),
                                                Text(
                                                  item.login,
                                                  style: const TextStyle(
                                                    fontSize: 12,
                                                    color: Color(0xFF94A3B8),
                                                  ),
                                                ),
                                              ],
                                            ),
                                          ),
                                          Expanded(
                                            flex: 3,
                                            child: Row(
                                              children: [
                                                Expanded(
                                                  child: Text(
                                                    isVisible
                                                        ? item.password
                                                        : '••••••••••••••••',
                                                    style: TextStyle(
                                                      fontSize: 12,
                                                      fontFamily: isVisible
                                                          ? 'monospace'
                                                          : null,
                                                      color: const Color(
                                                        0xFFCBD5E1,
                                                      ),
                                                    ),
                                                  ),
                                                ),
                                                IconButton(
                                                  icon: Icon(
                                                    isVisible
                                                        ? Icons
                                                              .visibility_off_outlined
                                                        : Icons
                                                              .visibility_outlined,
                                                    size: 16,
                                                    color: const Color(
                                                      0xFF3B82F6,
                                                    ),
                                                  ),
                                                  onPressed: () => setState(
                                                    () =>
                                                        _showPasswordList[index] =
                                                            !isVisible,
                                                  ),
                                                ),
                                                IconButton(
                                                  icon: const Icon(
                                                    Icons.copy_outlined,
                                                    size: 16,
                                                    color: Color(0xFF3B82F6),
                                                  ),
                                                  onPressed: () {
                                                    Clipboard.setData(
                                                      ClipboardData(
                                                        text: item.password,
                                                      ),
                                                    );
                                                    ScaffoldMessenger.of(
                                                      context,
                                                    ).showSnackBar(
                                                      const SnackBar(
                                                        content: Text(
                                                          '📋 Пароль скопирован!',
                                                        ),
                                                        duration: Duration(
                                                          seconds: 1,
                                                        ),
                                                      ),
                                                    );
                                                  },
                                                ),
                                                IconButton(
                                                  icon: const Icon(
                                                    Icons.delete_outline,
                                                    size: 16,
                                                    color: Color(0xFFEF4444),
                                                  ),
                                                  onPressed: () =>
                                                      _deletePassword(index),
                                                ),
                                              ],
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),
                                  );
                                },
                              ),
                            ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
