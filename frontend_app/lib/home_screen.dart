import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'account_management_dialog.dart';
import 'widgets/operation_stopwatch.dart';
import 'services/auth_service.dart';
import 'services/app_logger.dart';
import 'services/error_mapper.dart';
import 'main.dart';
import 'rust/api/clients/vault_client.dart';
import 'rust/api/clients/crypto_client.dart';
import 'rust/api/types/master_key.dart';
import 'rust/api/types/blob.dart';
import 'rust/api/types/crypto.dart' as rust_crypto;
import 'rust/api/types/errors.dart';
import 'services/local_vault_storage.dart';
import 'services/memory_protection_service.dart';

// Keep legacy diagnostic calls routed through the redacting logger.
void debugPrint(String? message, {int? wrapWidth}) {
  AppLogger.error('Dart diagnostic event: ${message ?? '<empty>'}');
}

void debugPrintStack({StackTrace? stackTrace}) {
  AppLogger.error('Dart diagnostic stack trace.', stackTrace: stackTrace);
}

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
  List<PasswordItem> _baseVaultPasswords = [];
  bool _isLoadingVault = true;
  bool _isSavingVault = false;
  bool _isSyncing = false;
  bool _isBackgroundRefreshing = false;
  String _activityStatus = 'Подготовка хранилища…';
  int _saveCountdownSeconds = 0;

  /// Хранилище успешно скачано и расшифровано. Пока это false, сохранять
  /// нельзя — иначе можно затереть серверные данные пустым списком.
  bool _vaultReady = false;
  String? _vaultError;

  // Последняя известная версия блоба на сервере.
  // В FRB 2.13 PlatformInt64 на Dart-стороне является обычным int.
  int _currentVaultVersion = 0;

  late List<bool> _showPasswordList;
  bool _isLoggingOut = false;
  CryptoKey? _cryptoKey;
  bool _memoryLocked = false;
  final ScrollController _scrollController = ScrollController();

  // Очередь сохранений: параллельные вызовы объединяются, а версия блоба
  // увеличивается строго последовательно.
  Future<void>? _saveChain;
  bool _saveQueued = false;
  Timer? _saveDebounceTimer;
  Timer? _backgroundSyncTimer;
  Timer? _clipboardClearTimer;
  int _clipboardGeneration = 0;
  bool _hasPendingSave = false;
  int _changeRevision = 0;

  @override
  void initState() {
    super.initState();
    _cryptoKey = widget.cryptoKey;
    AuthService().registerActiveCryptoKey(_cryptoKey);
    MemoryProtectionService().addListener(_onMemoryProtectionChanged);
    AuthService().addListener(_onNetworkModeChanged);
    _showPasswordList = [];
    _loadVaultFromBackend();
    _backgroundSyncTimer = Timer.periodic(
      const Duration(minutes: 1),
      (_) => _refreshVaultInBackground(),
    );
  }

  @override
  void dispose() {
    _saveDebounceTimer?.cancel();
    _backgroundSyncTimer?.cancel();
    _clipboardClearTimer?.cancel();
    unawaited(_clearOwnedClipboard());
    _scrollController.dispose();
    MemoryProtectionService().removeListener(_onMemoryProtectionChanged);
    AuthService().removeListener(_onNetworkModeChanged);
    unawaited(AuthService().zeroizeActiveCryptoKey());
    super.dispose();
  }

  void _onNetworkModeChanged() {
    if (!mounted ||
        AuthService().isOfflineMode ||
        !_vaultReady ||
        _memoryLocked ||
        _cryptoKey == null) {
      return;
    }
    unawaited(_fetchVault(showFeedback: true, keepDataOnError: true));
  }

  void _onMemoryProtectionChanged() {
    if (!mounted) return;
    if (MemoryProtectionService().isLocked) {
      _clipboardClearTimer?.cancel();
      unawaited(_clearOwnedClipboard());
      _copiedPassword = null;
      setState(() {
        _memoryLocked = true;
        _cryptoKey = null;
        _passwords = [];
        _baseVaultPasswords = [];
        _vaultReady = false;
        _isLoadingVault = false;
        _updatePasswordListState();
      });
      return;
    }
    unawaited(_restoreSensitiveMemory());
  }

  Future<void> _restoreSensitiveMemory() async {
    final credentials = await LocalVaultStorage.instance.readCredentials();
    if (!mounted || credentials == null) return;
    try {
      final userPassword = await UserPassword.newInstance(
        password: credentials.$2,
      );
      final key = await CryptoKey.fromUserPassword(
        userPassword: userPassword,
        username: credentials.$1,
      );
      if (!mounted || MemoryProtectionService().isLocked) {
        await key.zeroize();
        return;
      }
      _cryptoKey = key;
      AuthService().registerActiveCryptoKey(key);
      setState(() {
        _memoryLocked = false;
        _isLoadingVault = true;
      });
      await _fetchVault(showFeedback: false, keepDataOnError: true);
    } catch (error, stackTrace) {
      AppLogger.error(
        'Sensitive memory restore failed.',
        error: error,
        stackTrace: stackTrace,
      );
    }
  }

  Future<void> _clearOwnedClipboard() async {
    final generation = _clipboardGeneration;
    final clipboard = await Clipboard.getData(Clipboard.kTextPlain);
    if (generation == _clipboardGeneration &&
        clipboard?.text == _copiedPassword) {
      await Clipboard.setData(const ClipboardData(text: ''));
    }
  }

  String? _copiedPassword;

  Future<void> _copyPassword(String password) async {
    _clipboardClearTimer?.cancel();
    final generation = ++_clipboardGeneration;
    _copiedPassword = password;
    await Clipboard.setData(ClipboardData(text: password));

    _clipboardClearTimer = Timer(const Duration(seconds: 30), () async {
      if (generation != _clipboardGeneration) return;
      final clipboard = await Clipboard.getData(Clipboard.kTextPlain);
      if (generation == _clipboardGeneration && clipboard?.text == password) {
        await Clipboard.setData(const ClipboardData(text: ''));
        _copiedPassword = null;
      }
    });
  }

  void _updatePasswordListState() {
    _showPasswordList = List.generate(_passwords.length, (_) => false);
  }

  String? _resolveAccessToken() =>
      AuthService().accessToken ?? widget.accessToken;

  Future<void> _cacheBlob(Blob blob, {int? version}) async {
    try {
      await LocalVaultStorage.instance.saveBlob(
        await blob.serializeCbor(),
        version: version,
      );
    } catch (error) {
      debugPrint('Failed to save local blob: $error');
    }
  }

  bool get _isDemoSession =>
      _cryptoKey == null && _resolveAccessToken() == null;

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

  // Kept for compatibility with older UI text while all current paths use
  // the redacted error mapper below.
  // ignore: unused_element
  String _legacyDescribeError(Object error) {
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

  String _describeError(Object error) => describeAppError(error);

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
      if (error is SdkError_Network) AuthService().setOfflineMode(true);
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
    if (_hasPendingSave) {
      _showSnack(
        'Сначала дождитесь отправки локальных изменений, чтобы не потерять их.',
        isError: true,
      );
      return;
    }

    if (_cryptoKey == null) {
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

  Future<void> _refreshVaultInBackground() async {
    if (!mounted ||
        AuthService().isOfflineMode ||
        !_vaultReady ||
        _hasPendingSave ||
        _isSavingVault ||
        _isSyncing ||
        _isBackgroundRefreshing ||
        _cryptoKey == null ||
        _resolveAccessToken() == null) {
      return;
    }

    _isBackgroundRefreshing = true;
    if (mounted) {
      setState(() => _activityStatus = 'Фоновое обновление хранилища…');
    }
    try {
      final vaultClient = await AuthService().createVaultClient();
      final blob = await _withTokenRetry(
        (accessToken) => vaultClient.download(accessToken: accessToken),
      );
      final metadata = await _withTokenRetry(
        (accessToken) => vaultClient.getMetadata(accessToken: accessToken),
      );
      if (!mounted ||
          _hasPendingSave ||
          _isSavingVault ||
          metadata.version <= _currentVaultVersion) {
        return;
      }
      await _cacheBlob(blob, version: metadata.version);

      final cryptoClient = await CryptoClient.newInstance();
      final keys = await cryptoClient.decryptKeys(
        cryptoKey: _cryptoKey!,
        blob: blob,
      );
      if (!mounted ||
          _hasPendingSave ||
          _isSavingVault ||
          metadata.version <= _currentVaultVersion) {
        return;
      }

      setState(() {
        _passwords = keys.keys.map(PasswordItem.fromRustKey).toList();
        _baseVaultPasswords = List.of(_passwords);
        _currentVaultVersion = metadata.version;
        _updatePasswordListState();
        _activityStatus = 'Получены изменения с сервера';
      });
    } catch (error, stackTrace) {
      debugPrint('Vault background refresh failed: $error');
      debugPrintStack(stackTrace: stackTrace);
    } finally {
      _isBackgroundRefreshing = false;
      if (mounted && !_isSavingVault && !_hasPendingSave) {
        setState(() => _activityStatus = 'Хранилище готово');
      }
    }
  }

  Future<bool> _fetchVault({
    required bool showFeedback,
    bool keepDataOnError = false,
  }) async {
    final cryptoKey = _cryptoKey;

    if (AuthService().isOfflineMode) {
      if (cryptoKey != null &&
          await _restoreCachedVault(cryptoKey, showFeedback: showFeedback)) {
        return true;
      }
      if (mounted) {
        setState(() {
          _isLoadingVault = false;
          _vaultReady = false;
          _vaultError =
              'Офлайн-режим: локальный зашифрованный blob недоступен.';
          _activityStatus = 'Офлайн-режим';
        });
      }
      return false;
    }

    if (cryptoKey == null) {
      if (mounted) {
        setState(() {
          _isLoadingVault = false;
          _vaultReady = false;
          _vaultError = _isDemoSession
              ? 'Демо-вход admin/admin: серверное хранилище недоступно. Войдите реальным аккаунтом.'
              : 'Ключ хранилища недоступен. Войдите по паролю или Passkey с паролем.';
          _activityStatus = 'Хранилище недоступно';
        });
      }
      if (showFeedback) {
        _showSnack(
          _isDemoSession ? 'Демо-вход admin/admin не подключён к серверу.' : 'Для просмотра паролей нужен ключ хранилища. Войдите с паролем.',
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
          _activityStatus = 'Сессия не найдена';
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
        _activityStatus = 'Загрузка хранилища…';
      });
    }

    try {
      final vaultClient = await AuthService().createVaultClient();
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
          _baseVaultPasswords = [];
          _updatePasswordListState();
          _vaultReady = true;
          _vaultError = null;
          _isLoadingVault = false;
          _activityStatus = 'Хранилище готово';
        });
        if (showFeedback) {
          _showSnack(
            'На сервере пока нет сохранённых паролей.',
            isError: false,
          );
        }
        return true;
      }

      Blob blob;
      late rust_crypto.Keys keys;
      var usedCachedBlob = false;
      final cachedVersion = await LocalVaultStorage.instance.readBlobVersion();
      final cachedEncoded = await LocalVaultStorage.instance.readBlob();

      if (cachedEncoded != null &&
          cachedEncoded.isNotEmpty &&
          cachedVersion == storedVersion) {
        try {
          blob = await Blob.deserializeCbor(encoded: cachedEncoded.toList());
          keys = await cryptoClient.decryptKeys(
            cryptoKey: cryptoKey,
            blob: blob,
          );
          usedCachedBlob = true;
        } catch (error) {
          AppLogger.error(
            'Cached blob is invalid; downloading a fresh version.',
            error: error,
          );
          usedCachedBlob = false;
        }
      }

      if (!usedCachedBlob) {
        blob = await _withTokenRetry(
          (accessToken) => vaultClient.download(accessToken: accessToken),
        );
        await _cacheBlob(blob, version: storedVersion);
        keys = await cryptoClient.decryptKeys(cryptoKey: cryptoKey, blob: blob);
      }

      // decryptKeys возвращает Keys напрямую и не требует работы с TbsBlob.
      AppLogger.info(
        usedCachedBlob ? 'Использован локальный blob совпадающей версии.' : 'Локальный blob отсутствует или устарел, загружена версия сервера.',
      );

      if (!mounted) return true;

      setState(() {
        _currentVaultVersion = storedVersion;
        _passwords = keys.keys
            .map((key) => PasswordItem.fromRustKey(key))
            .toList();
        _baseVaultPasswords = List.of(_passwords);
        _updatePasswordListState();
        _vaultReady = true;
        _vaultError = null;
        _isLoadingVault = false;
        _activityStatus = 'Хранилище готово';
      });

      if (showFeedback) {
        _showSnack(
          'Хранилище синхронизировано: ${_passwords.length} записей.',
          isError: false,
        );
      }
      return true;
    } catch (error, stackTrace) {
      debugPrint('Vault load or decryption failed: $error');
      debugPrintStack(stackTrace: stackTrace);

      if (await _restoreCachedVault(cryptoKey, showFeedback: showFeedback)) {
        return true;
      }
      if (!mounted) return false;

      setState(() {
        _vaultReady = false;
        _vaultError = _describeError(error);
        _isLoadingVault = false;
        _activityStatus = 'Ошибка загрузки хранилища';
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
  Future<bool> _restoreCachedVault(
    CryptoKey cryptoKey, {
    required bool showFeedback,
  }) async {
    try {
      final encoded = await LocalVaultStorage.instance.readBlob();
      if (encoded == null || encoded.isEmpty) return false;
      final blob = await Blob.deserializeCbor(encoded: encoded.toList());
      final cryptoClient = await CryptoClient.newInstance();
      final keys = await cryptoClient.decryptKeys(
        cryptoKey: cryptoKey,
        blob: blob,
      );
      final version = await LocalVaultStorage.instance.readBlobVersion();
      if (!mounted) return false;
      setState(() {
        _currentVaultVersion = version;
        _passwords = keys.keys.map(PasswordItem.fromRustKey).toList();
        _baseVaultPasswords = List.of(_passwords);
        _updatePasswordListState();
        _vaultReady = true;
        _vaultError = null;
        _isLoadingVault = false;
        _activityStatus = 'Офлайн-кеш: сервер временно недоступен';
      });
      if (showFeedback) {
        _showSnack(
          'Показан локальный зашифрованный кеш. Изменения синхронизируются после восстановления связи.',
        );
      }
      return true;
    } catch (error) {
      debugPrint('Local cache decryption failed: $error');
      return false;
    }
  }

  void _requestVaultSave() {
    if (AuthService().isOfflineMode) {
      _showSnack(
        'Офлайн-режим: изменения не отправляются на сервер.',
        isError: true,
      );
      return;
    }
    _hasPendingSave = true;
    _saveDebounceTimer?.cancel();
    _saveCountdownSeconds = 30;
    if (mounted) {
      setState(() {
        _activityStatus = 'Синхронизация через 30 секунд';
      });
    }
    _saveDebounceTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (!mounted || _saveCountdownSeconds <= 1) {
        timer.cancel();
        _saveCountdownSeconds = 0;
        _queueVaultSave();
        return;
      }
      setState(() {
        _saveCountdownSeconds--;
        _activityStatus = 'Синхронизация через $_saveCountdownSeconds секунд';
      });
    });
  }

  void _queueVaultSave() {
    if (AuthService().isOfflineMode) return;
    _saveDebounceTimer?.cancel();
    _saveCountdownSeconds = 0;
    if (_saveChain != null) {
      _saveQueued = true;
      return;
    }

    _saveChain = _runVaultSaveLoop().whenComplete(() {
      _saveChain = null;
    });
  }

  void _forceSaveNow() {
    if (!_hasPendingSave || _isSavingVault) return;
    _saveDebounceTimer?.cancel();
    _saveCountdownSeconds = 0;
    if (mounted) {
      setState(() => _activityStatus = 'Запускаю синхронизацию…');
    }
    _queueVaultSave();
  }

  Future<void> _runVaultSaveLoop() async {
    do {
      _saveQueued = false;
      await _saveVaultToBackend();
      // Если во время сохранения список изменился — сохраняем ещё раз.
    } while (_saveQueued && mounted);
  }

  Future<void> _saveVaultToBackend() async {
    final cryptoKey = _cryptoKey;

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
      setState(() {
        _isSavingVault = true;
        _activityStatus = 'Шифрование хранилища…';
      });
    }

    final revisionAtStart = _changeRevision;
    try {
      final vaultClient = await AuthService().createVaultClient();
      final cryptoClient = await CryptoClient.newInstance();
      final localPasswords = List<PasswordItem>.of(_passwords);

      final rust_crypto.Keys keys = rust_crypto.Keys(
        keys: localPasswords.map((item) => item.toRustKey()).toList(),
      );

      // encryptKeys сам формирует соль/нонс и тег внутри Rust.
      final Blob newBlob = await cryptoClient.encryptKeys(
        cryptoKey: cryptoKey,
        keys: keys,
      );

      // Сервер требует версию строго больше сохранённой.
      if (mounted) {
        setState(() => _activityStatus = 'Синхронизация с сервером…');
      }
      final (savedVersion, mergedPasswords) = await _uploadVaultWithRetry(
        vaultClient,
        cryptoClient,
        localPasswords,
        newBlob,
      );
      _currentVaultVersion = savedVersion;
      _baseVaultPasswords = List.of(mergedPasswords);
      if (revisionAtStart == _changeRevision) {
        if (mounted) {
          setState(() {
            _passwords = List.of(mergedPasswords);
            _updatePasswordListState();
          });
        }
        _hasPendingSave = false;
      }

      if (mounted) {
        setState(() => _activityStatus = 'Хранилище готово');
        _showSnack(
          'Сохранено на сервере (версия $savedVersion).',
          isError: false,
        );
      }
    } catch (error, stackTrace) {
      debugPrint('Vault save failed: $error');
      debugPrintStack(stackTrace: stackTrace);

      if (mounted) {
        setState(
          () => _activityStatus = error is StateError
              ? 'Слияние версий не выполнено'
              : 'Ошибка синхронизации',
        );
        _showSnack(
          error is StateError
              ? 'Не удалось объединить версии: ${_describeError(error)}'
              : 'Не удалось сохранить: ${_describeError(error)}',
          isError: true,
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isSavingVault = false);
      }
    }
  }

  Future<(int, List<PasswordItem>)> _uploadVaultWithRetry(
    VaultClient vaultClient,
    CryptoClient cryptoClient,
    List<PasswordItem> pendingPasswords,
    Blob blob,
  ) async {
    var version = _currentVaultVersion + 1;
    try {
      await _withTokenRetry(
        (accessToken) => vaultClient.upload(
          accessToken: accessToken,
          blob: blob,
          version: version,
        ),
      );
      return (version, pendingPasswords);
    } on SdkError catch (error) {
      final staleVersion =
          error is SdkError_Server &&
          (error.code == 'BLOB_VERSION_NOT_INCREASING' ||
              error.code == 'BLOB_VERSION_INVALID');
      if (!staleVersion) rethrow;

      if (mounted) {
        setState(() => _activityStatus = 'Проверка и объединение версий…');
      }
      final metadata = await _withTokenRetry(
        (accessToken) => vaultClient.getMetadata(accessToken: accessToken),
      );
      final serverBlob = await _withTokenRetry(
        (accessToken) => vaultClient.download(accessToken: accessToken),
      );
      final serverKeys = await cryptoClient.decryptKeys(
        cryptoKey: _cryptoKey!,
        blob: serverBlob,
      );
      final mergedPasswords = await _mergeVaultPasswords(
        pendingPasswords,
        serverKeys.keys.map(PasswordItem.fromRustKey).toList(),
      );
      if (mergedPasswords == null) {
        throw StateError(
          'Слияние отменено: выберите версию и повторите сохранение.',
        );
      }

      if (mounted) {
        setState(() {
          _passwords = mergedPasswords;
          _updatePasswordListState();
          _activityStatus = 'Шифрование объединённого хранилища…';
        });
      }
      final mergedBlob = await cryptoClient.encryptKeys(
        cryptoKey: _cryptoKey!,
        keys: rust_crypto.Keys(
          keys: mergedPasswords.map((item) => item.toRustKey()).toList(),
        ),
      );
      _currentVaultVersion = metadata.version;
      version = metadata.version + 1;

      await _withTokenRetry(
        (accessToken) => vaultClient.upload(
          accessToken: accessToken,
          blob: mergedBlob,
          version: version,
        ),
      );
      return (version, mergedPasswords);
    }
  }

  Future<List<PasswordItem>?> _mergeVaultPasswords(
    List<PasswordItem> localPasswords,
    List<PasswordItem> serverPasswords,
  ) async {
    String identity(PasswordItem item) =>
        '${item.title.trim().toLowerCase()}\u0000${item.login.trim().toLowerCase()}';
    bool sameEntry(PasswordItem first, PasswordItem second) =>
        first.title == second.title &&
        first.login == second.login &&
        first.password == second.password &&
        first.userComment == second.userComment;

    final baseByIdentity = <String, PasswordItem>{
      for (final item in _baseVaultPasswords) identity(item): item,
    };
    final localByIdentity = <String, PasswordItem>{
      for (final item in localPasswords) identity(item): item,
    };
    final serverByIdentity = <String, PasswordItem>{
      for (final item in serverPasswords) identity(item): item,
    };
    final mergedByIdentity = <String, PasswordItem>{};
    final conflicts = <String, ({PasswordItem? local, PasswordItem? server})>{};

    for (final key in {
      ...baseByIdentity.keys,
      ...localByIdentity.keys,
      ...serverByIdentity.keys,
    }) {
      final base = baseByIdentity[key];
      final local = localByIdentity[key];
      final server = serverByIdentity[key];
      if (base == null) {
        if (local != null && server != null && !sameEntry(local, server)) {
          conflicts[key] = (local: local, server: server);
        } else if (local != null || server != null) {
          mergedByIdentity[key] = local ?? server!;
        }
        continue;
      }

      final localChanged = local == null || !sameEntry(local, base);
      final serverChanged = server == null || !sameEntry(server, base);
      if (localChanged && serverChanged) {
        if (local == null && server == null) continue;
        if (local != null && server != null && sameEntry(local, server)) {
          mergedByIdentity[key] = local;
        } else {
          conflicts[key] = (local: local, server: server);
        }
      } else if (localChanged) {
        if (local != null) mergedByIdentity[key] = local;
      } else if (server != null) {
        mergedByIdentity[key] = server;
      }
    }

    if (conflicts.isEmpty) return mergedByIdentity.values.toList();
    final choices = await _showVaultMergeDialog(conflicts);
    if (choices == null) return null;

    for (final entry in conflicts.entries) {
      final chosen = choices[entry.key] == true
          ? entry.value.local
          : entry.value.server;
      if (chosen == null) {
        mergedByIdentity.remove(entry.key);
      } else {
        mergedByIdentity[entry.key] = chosen;
      }
    }
    return mergedByIdentity.values.toList();
  }

  Future<Map<String, bool>?> _showVaultMergeDialog(
    Map<String, ({PasswordItem? local, PasswordItem? server})> conflicts,
  ) {
    final choices = <String, bool>{for (final key in conflicts.keys) key: true};
    return showDialog<Map<String, bool>>(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          backgroundColor: const Color(0xFF18181B),
          title: const Text('Выберите записи для конфликтов'),
          content: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text(
                    'Другие изменения объединены автоматически. Для одинаковых записей выберите, оставить локальную или серверную версию.',
                    style: TextStyle(color: Color(0xFFA1A1AA)),
                  ),
                  const SizedBox(height: 12),
                  for (final entry in conflicts.entries)
                    Card(
                      color: const Color(0xFF202027),
                      child: Padding(
                        padding: const EdgeInsets.all(12),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              (entry.value.local ?? entry.value.server!).title,
                              style: const TextStyle(
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            Text(
                              (entry.value.local ?? entry.value.server!).login,
                              style: const TextStyle(
                                color: Color(0xFF94A3B8),
                                fontSize: 12,
                              ),
                            ),
                            RadioGroup<bool>(
                              groupValue: choices[entry.key],
                              onChanged: (value) {
                                if (value != null) {
                                  setDialogState(
                                    () => choices[entry.key] = value,
                                  );
                                }
                              },
                              child: Column(
                                children: [
                                  RadioListTile<bool>(
                                    contentPadding: EdgeInsets.zero,
                                    dense: true,
                                    value: true,
                                    title: Text(
                                      entry.value.local == null
                                          ? 'Удалить запись локально'
                                          : 'Оставить локальную версию',
                                    ),
                                  ),
                                  RadioListTile<bool>(
                                    contentPadding: EdgeInsets.zero,
                                    dense: true,
                                    value: false,
                                    title: Text(
                                      entry.value.server == null
                                          ? 'Удалить запись с сервера'
                                          : 'Оставить версию с сервера',
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(dialogContext, choices),
              child: const Text('Объединить и сохранить'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _handleLogout() async {
    _saveDebounceTimer?.cancel();
    if (_hasPendingSave) {
      _queueVaultSave();
      final pendingSave = _saveChain;
      if (pendingSave != null) await pendingSave;
      if (_hasPendingSave) {
        _showSnack(
          'Выход отменён: изменения не удалось синхронизировать. Проверьте соединение и повторите.',
          isError: true,
        );
        return;
      }
    }

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
                    _changeRevision++;
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
                  _changeRevision++;
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

  void _showAccountManagementDialog() {
    final accessToken = _resolveAccessToken();
    if (accessToken == null) return;
    showDialog<void>(
      context: context,
      builder: (context) => AccountManagementDialog(
        username: widget.username,
        accessToken: accessToken,
        cryptoKey: _cryptoKey,
        onAccountDeleted: () {
          Navigator.pushAndRemoveUntil(
            this.context,
            MaterialPageRoute(builder: (context) => const AuthScreen()),
            (route) => false,
          );
        },
      ),
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
              if (_resolveAccessToken() != null) ...[
                const SizedBox(height: 18),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton.icon(
                    onPressed: () {
                      Navigator.pop(dialogContext);
                      _showAccountManagementDialog();
                    },
                    icon: const Icon(Icons.manage_accounts, size: 17),
                    label: const Text('Passkeys, события и аккаунт'),
                  ),
                ),
              ],
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
      children: [
        Expanded(
          child: Text(
            label,
            style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
          ),
        ),
        Flexible(
          child: Text(
            value,
            textAlign: TextAlign.end,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(
              color: Color(0xFFFAFAFA),
              fontSize: 13,
              fontWeight: FontWeight.bold,
            ),
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
      _changeRevision++;
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
    final hasKey = _cryptoKey != null;

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

  Widget _buildPasswordActions({
    required int index,
    required PasswordItem item,
    required bool isVisible,
    required bool compact,
  }) {
    final constraints = compact
        ? const BoxConstraints.tightFor(width: 36, height: 36)
        : null;
    final padding = compact ? EdgeInsets.zero : null;

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        IconButton(
          constraints: constraints,
          padding: padding,
          tooltip: isVisible ? 'Скрыть пароль' : 'Показать пароль',
          icon: Icon(
            isVisible
                ? Icons.visibility_off_outlined
                : Icons.visibility_outlined,
            size: 16,
            color: const Color(0xFF3B82F6),
          ),
          onPressed: () =>
              setState(() => _showPasswordList[index] = !isVisible),
        ),
        IconButton(
          constraints: constraints,
          padding: padding,
          tooltip: 'Скопировать пароль',
          icon: const Icon(
            Icons.copy_outlined,
            size: 16,
            color: Color(0xFF3B82F6),
          ),
          onPressed: () {
            unawaited(_copyPassword(item.password));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('📋 Пароль скопирован!'),
                duration: Duration(seconds: 1),
              ),
            );
          },
        ),
        IconButton(
          constraints: constraints,
          padding: padding,
          tooltip: 'Удалить пароль',
          icon: const Icon(
            Icons.delete_outline,
            size: 16,
            color: Color(0xFFEF4444),
          ),
          onPressed: () => _deletePassword(index),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final isPhoneWidth = MediaQuery.sizeOf(context).width < 600;
    return Scaffold(
      backgroundColor: const Color(0xFF09090E),
      body: _memoryLocked
          ? _buildMemoryLockedScreen()
          : SafeArea(
              child: Column(
                children: [
                  Container(
                    padding: EdgeInsets.symmetric(
                      horizontal: isPhoneWidth ? 12 : 24,
                      vertical: 14,
                    ),
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
                        Text(
                          'RustVault',
                          style: TextStyle(
                            fontSize: isPhoneWidth ? 16 : 18,
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
                          if (!isPhoneWidth)
                            const Text(
                              'Сохранение…',
                              style: TextStyle(
                                fontSize: 12,
                                color: Color(0xFF94A3B8),
                              ),
                            ),
                          SizedBox(width: isPhoneWidth ? 4 : 12),
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
                              border: Border.all(
                                color: const Color(0xFF3B82F6),
                              ),
                            ),
                            child: Row(
                              children: [
                                const Icon(
                                  Icons.person_outline,
                                  size: 15,
                                  color: Color(0xFF3B82F6),
                                ),
                                const SizedBox(width: 6),
                                ConstrainedBox(
                                  constraints: BoxConstraints(
                                    maxWidth: isPhoneWidth ? 96 : 180,
                                  ),
                                  child: Text(
                                    widget.username,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: const TextStyle(
                                      fontSize: 13,
                                      fontWeight: FontWeight.w600,
                                      color: Color(0xFFFAFAFA),
                                    ),
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
                      padding: EdgeInsets.symmetric(
                        horizontal: isPhoneWidth ? 12 : 24,
                        vertical: isPhoneWidth ? 12 : 20,
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.symmetric(
                              horizontal: 14,
                              vertical: 10,
                            ),
                            decoration: BoxDecoration(
                              color: const Color(0xFF111827),
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(
                                color: _activityStatus.startsWith('Ошибка')
                                    ? const Color(0xFF7F1D1D)
                                    : const Color(0xFF1E3A5F),
                              ),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                Row(
                                  children: [
                                    if (_isLoadingVault ||
                                        _isSavingVault ||
                                        _isSyncing)
                                      const SizedBox(
                                        width: 16,
                                        height: 16,
                                        child: CircularProgressIndicator(
                                          strokeWidth: 2,
                                        ),
                                      )
                                    else
                                      Icon(
                                        _activityStatus.startsWith('Ошибка')
                                            ? Icons.error_outline
                                            : Icons.cloud_done_outlined,
                                        size: 18,
                                        color:
                                            _activityStatus.startsWith('Ошибка')
                                            ? const Color(0xFFF87171)
                                            : const Color(0xFF60A5FA),
                                      ),
                                    const SizedBox(width: 10),
                                    Expanded(
                                      child: Text(
                                        _activityStatus,
                                        maxLines: 2,
                                        overflow: TextOverflow.ellipsis,
                                        style: const TextStyle(
                                          color: Color(0xFFCBD5E1),
                                          fontSize: 12,
                                        ),
                                      ),
                                    ),
                                    if (_isLoadingVault ||
                                        _isSavingVault ||
                                        _isSyncing ||
                                        _isBackgroundRefreshing) ...[
                                      const SizedBox(width: 8),
                                      const OperationStopwatch(running: true),
                                    ],
                                    if (_hasPendingSave)
                                      TextButton(
                                        onPressed: _isSavingVault
                                            ? null
                                            : _forceSaveNow,
                                        child: const Text(
                                          'Синхронизировать сейчас',
                                          style: TextStyle(fontSize: 11),
                                        ),
                                      )
                                    else if (_activityStatus.startsWith(
                                      'Ошибка',
                                    ))
                                      IconButton(
                                        tooltip: 'Повторить синхронизацию',
                                        onPressed: _isSavingVault
                                            ? null
                                            : _queueVaultSave,
                                        icon: const Icon(
                                          Icons.refresh,
                                          size: 18,
                                        ),
                                      ),
                                  ],
                                ),
                                if (_saveCountdownSeconds > 0) ...[
                                  const SizedBox(height: 8),
                                  TweenAnimationBuilder<double>(
                                    tween: Tween<double>(
                                      begin: 0,
                                      end: 1 - _saveCountdownSeconds / 30,
                                    ),
                                    duration: const Duration(seconds: 1),
                                    curve: Curves.easeInOut,
                                    builder: (context, progress, child) =>
                                        LinearProgressIndicator(
                                          value: progress,
                                          minHeight: 5,
                                          backgroundColor: const Color(
                                            0xFF1E293B,
                                          ),
                                          valueColor:
                                              const AlwaysStoppedAnimation(
                                                Color(0xFF60A5FA),
                                              ),
                                          borderRadius: BorderRadius.circular(
                                            8,
                                          ),
                                        ),
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    'Осталось $_saveCountdownSeconds сек.',
                                    textAlign: TextAlign.end,
                                    style: const TextStyle(
                                      color: Color(0xFF94A3B8),
                                      fontSize: 10,
                                    ),
                                  ),
                                ],
                              ],
                            ),
                          ),
                          const SizedBox(height: 14),
                          Wrap(
                            spacing: 8,
                            runSpacing: 4,
                            crossAxisAlignment: WrapCrossAlignment.center,
                            children: [
                              Text(
                                '🔐 Мои пароли',
                                style: TextStyle(
                                  fontSize: isPhoneWidth ? 18 : 20,
                                  fontWeight: FontWeight.bold,
                                  color: Color(0xFFFAFAFA),
                                ),
                              ),
                              IconButton(
                                tooltip: 'Синхронизировать с сервером',
                                onPressed:
                                    (_isSyncing ||
                                        _isLoadingVault ||
                                        _cryptoKey == null)
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
                              ElevatedButton.icon(
                                onPressed:
                                    (_cryptoKey == null ||
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
                                        final isVisible =
                                            _showPasswordList[index];

                                        return GestureDetector(
                                          onTap: () =>
                                              _showEditPasswordDialog(index),
                                          child: Container(
                                            padding: const EdgeInsets.symmetric(
                                              horizontal: 14,
                                              vertical: 10,
                                            ),
                                            decoration: BoxDecoration(
                                              color: const Color(0xFF121218),
                                              borderRadius:
                                                  BorderRadius.circular(10),
                                              border: Border.all(
                                                color: const Color(0xFF1E293B),
                                              ),
                                            ),
                                            child: isPhoneWidth
                                                ? Column(
                                                    crossAxisAlignment:
                                                        CrossAxisAlignment
                                                            .stretch,
                                                    children: [
                                                      Row(
                                                        children: [
                                                          Expanded(
                                                            child: Column(
                                                              crossAxisAlignment:
                                                                  CrossAxisAlignment
                                                                      .start,
                                                              children: [
                                                                Text(
                                                                  item.title,
                                                                  maxLines: 1,
                                                                  overflow:
                                                                      TextOverflow
                                                                          .ellipsis,
                                                                  style: const TextStyle(
                                                                    fontWeight:
                                                                        FontWeight
                                                                            .bold,
                                                                    color: Color(
                                                                      0xFFFAFAFA,
                                                                    ),
                                                                  ),
                                                                ),
                                                                const SizedBox(
                                                                  height: 2,
                                                                ),
                                                                Text(
                                                                  item.login,
                                                                  maxLines: 1,
                                                                  overflow:
                                                                      TextOverflow
                                                                          .ellipsis,
                                                                  style: const TextStyle(
                                                                    fontSize:
                                                                        12,
                                                                    color: Color(
                                                                      0xFF94A3B8,
                                                                    ),
                                                                  ),
                                                                ),
                                                              ],
                                                            ),
                                                          ),
                                                          _buildPasswordActions(
                                                            index: index,
                                                            item: item,
                                                            isVisible:
                                                                isVisible,
                                                            compact: true,
                                                          ),
                                                        ],
                                                      ),
                                                      const SizedBox(height: 6),
                                                      Text(
                                                        isVisible
                                                            ? item.password
                                                            : '••••••••••••••••',
                                                        maxLines: 1,
                                                        overflow: TextOverflow
                                                            .ellipsis,
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
                                                    ],
                                                  )
                                                : Row(
                                                    children: [
                                                      Expanded(
                                                        flex: 2,
                                                        child: Column(
                                                          crossAxisAlignment:
                                                              CrossAxisAlignment
                                                                  .start,
                                                          children: [
                                                            Text(
                                                              item.title,
                                                              style: const TextStyle(
                                                                fontWeight:
                                                                    FontWeight
                                                                        .bold,
                                                                color: Color(
                                                                  0xFFFAFAFA,
                                                                ),
                                                              ),
                                                            ),
                                                            const SizedBox(
                                                              height: 2,
                                                            ),
                                                            Text(
                                                              item.login,
                                                              style:
                                                                  const TextStyle(
                                                                    fontSize:
                                                                        12,
                                                                    color: Color(
                                                                      0xFF94A3B8,
                                                                    ),
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
                                                                  fontFamily:
                                                                      isVisible
                                                                      ? 'monospace'
                                                                      : null,
                                                                  color: const Color(
                                                                    0xFFCBD5E1,
                                                                  ),
                                                                ),
                                                              ),
                                                            ),
                                                            _buildPasswordActions(
                                                              index: index,
                                                              item: item,
                                                              isVisible:
                                                                  isVisible,
                                                              compact: false,
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

  Widget _buildMemoryLockedScreen() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(28),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.lock, size: 54, color: Color(0xFF60A5FA)),
            const SizedBox(height: 18),
            const Text(
              'Sensitive data is locked',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            const Text(
              'The vault was removed from memory while the app was inactive. Restoring it…',
              style: TextStyle(color: Color(0xFF94A3B8)),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 22),
            const CircularProgressIndicator(color: Color(0xFF60A5FA)),
          ],
        ),
      ),
    );
  }
}
