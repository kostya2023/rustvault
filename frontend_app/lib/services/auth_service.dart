import 'dart:async';

import 'package:flutter/foundation.dart';

import '../rust/api/clients/account_client.dart';
import '../rust/api/clients/auth_client.dart';
import '../rust/api/clients/health_client.dart';
import '../rust/api/clients/security_client.dart';
import '../rust/api/clients/vault_client.dart';
import '../rust/api/types/errors.dart';
import '../rust/api/types/master_key.dart';
import 'app_logger.dart';
import 'local_vault_storage.dart';

class AuthService extends ChangeNotifier {
  static final AuthService _instance = AuthService._internal();
  factory AuthService() => _instance;
  AuthService._internal();

  String? _accessToken;
  String? _refreshToken;
  Timer? _refreshTimer;
  Timer? _offlineHealthTimer;

  String _baseUrl = 'http://localhost:80';
  Uint8List? _sslCaPinnedCert;
  String? _sslCaPinnedCertPath;
  bool _isReleaseConfigurationLocked = false;
  bool _isRefreshing = false;
  bool _cachedSessionInvalid = false;
  CryptoKey? _activeCryptoKey;
  bool _offlineMode = false;
  bool _isHealthChecking = false;
  bool _sessionExpired = false;
  bool _isAutoLoggingOut = false;

  String? get accessToken => _accessToken;
  String? get refreshToken => _refreshToken;
  String get baseUrl => _baseUrl;
  Uint8List? get sslCaPinnedCert => _sslCaPinnedCert;
  String? get sslCaPinnedCertPath => _sslCaPinnedCertPath;
  bool get isOfflineMode => _offlineMode;
  bool get sessionExpired => _sessionExpired;

  void setOfflineMode(bool value) {
    if (_offlineMode == value) return;
    _offlineMode = value;
    AppLogger.warning(
      value
          ? 'Offline mode enabled.'
          : 'Offline mode disabled after health check.',
    );
    if (_offlineMode) {
      _offlineHealthTimer ??= Timer.periodic(
        const Duration(seconds: 30),
        (_) => unawaited(checkServerHealth()),
      );
    } else {
      _offlineHealthTimer?.cancel();
      _offlineHealthTimer = null;
    }
    notifyListeners();
  }

  Future<bool> checkServerHealth() async {
    if (_isHealthChecking) return !_offlineMode;
    _isHealthChecking = true;
    try {
      final health = await createHealthClient();
      await health.check();
      setOfflineMode(false);
      return true;
    } catch (error) {
      setOfflineMode(true);
      AppLogger.warning(
        'Health check failed; staying in offline mode.',
        error: error,
      );
      return false;
    } finally {
      _isHealthChecking = false;
    }
  }

  void _ensureNetworkAvailable() {
    if (_offlineMode) {
      throw StateError('OFFLINE_MODE_NETWORK_BLOCKED');
    }
  }

  void registerActiveCryptoKey(CryptoKey? cryptoKey) {
    _activeCryptoKey = cryptoKey;
  }

  Future<void> zeroizeActiveCryptoKey() async {
    final cryptoKey = _activeCryptoKey;
    _activeCryptoKey = null;
    if (cryptoKey != null) await cryptoKey.zeroize();
  }

  Future<void> suspendSensitiveSession() async {
    _refreshTimer?.cancel();
    _accessToken = null;
    _refreshToken = null;
    await zeroizeActiveCryptoKey();
  }

  Future<bool> restoreSuspendedSession({bool refresh = true}) async {
    await restoreSession(refresh: refresh);
    return _accessToken != null;
  }

  set baseUrl(String value) {
    _ensureConfigurationCanChange();
    _baseUrl = value;
  }

  void setSslCaPinnedCert(Uint8List? certificate, {String? path}) {
    _ensureConfigurationCanChange();
    _sslCaPinnedCert = certificate;
    _sslCaPinnedCertPath = certificate == null ? null : path;
  }

  void configureRelease({
    required String baseUrl,
    required Uint8List sslCaPinnedCert,
  }) {
    if (_isReleaseConfigurationLocked) {
      throw StateError('Release API configuration is already locked.');
    }
    _baseUrl = baseUrl;
    _sslCaPinnedCert = sslCaPinnedCert;
    _sslCaPinnedCertPath = 'assets/certificates/ca.crt';
    _isReleaseConfigurationLocked = true;
  }

  void _ensureConfigurationCanChange() {
    if (_isReleaseConfigurationLocked) {
      throw StateError('API configuration is locked in the release build.');
    }
  }

  Future<AccountClient> createAccountClient() async {
    _ensureNetworkAvailable();
    return AccountClient.withBaseUrlAndRootOfTrust(
      baseUrl: _baseUrl,
      sslCaPinnedCert: _sslCaPinnedCert,
    );
  }

  Future<LoginWithPasstotpClient> createLoginWithPasstotpClient() async {
    _ensureNetworkAvailable();
    return LoginWithPasstotpClient.withBaseUrlAndRootOfTrust(
      baseUrl: _baseUrl,
      sslCaPinnedCert: _sslCaPinnedCert,
    );
  }

  Future<LoginWithPasskeyClient> createLoginWithPasskeyClient() async {
    _ensureNetworkAvailable();
    return LoginWithPasskeyClient.withBaseUrlAndRootOfTrust(
      baseUrl: _baseUrl,
      sslCaPinnedCert: _sslCaPinnedCert,
    );
  }

  Future<RegistrationWithPasstotpClient> createRegistrationClient() async {
    _ensureNetworkAvailable();
    return RegistrationWithPasstotpClient.withBaseUrlAndRootOfTrust(
      baseUrl: _baseUrl,
      sslCaPinnedCert: _sslCaPinnedCert,
    );
  }

  Future<TokenClient> createTokenClient() async {
    _ensureNetworkAvailable();
    return TokenClient.withBaseUrlAndRootOfTrust(
      baseUrl: _baseUrl,
      sslCaPinnedCert: _sslCaPinnedCert,
    );
  }

  Future<HealthClient> createHealthClient() =>
      HealthClient.withBaseUrlAndRootOfTrust(
        baseUrl: _baseUrl,
        sslCaPinnedCert: _sslCaPinnedCert,
      );

  Future<SecurityClient> createSecurityClient() async {
    _ensureNetworkAvailable();
    return SecurityClient.withBaseUrlAndRootOfTrust(
      baseUrl: _baseUrl,
      sslCaPinnedCert: _sslCaPinnedCert,
    );
  }

  Future<VaultClient> createVaultClient() async {
    _ensureNetworkAvailable();
    return VaultClient.withBaseUrlAndRootOfTrust(
      baseUrl: _baseUrl,
      sslCaPinnedCert: _sslCaPinnedCert,
    );
  }

  Future<void> restoreSession({bool refresh = true}) async {
    final tokens = await LocalVaultStorage.instance.readTokens();
    if (tokens == null) return;
    _accessToken = tokens.$1;
    _refreshToken = tokens.$2;
    if (refresh) await performTokenRefresh();
  }

  void saveTokens(
    String accessToken,
    String refreshToken, {
    String? currentBaseUrl,
    int expiresInSeconds = 900,
  }) {
    _cachedSessionInvalid = false;
    _sessionExpired = false;
    _accessToken = accessToken;
    _refreshToken = refreshToken;
    if (currentBaseUrl != null) baseUrl = currentBaseUrl;
    _startRefreshTimer(expiresInSeconds);
    unawaited(LocalVaultStorage.instance.saveTokens(accessToken, refreshToken));
  }

  void _startRefreshTimer(int expiresInSeconds) {
    _refreshTimer?.cancel();
    int refreshDelay = (expiresInSeconds - 60) > 0
        ? (expiresInSeconds - 60)
        : (expiresInSeconds ~/ 2);
    if (refreshDelay < 10) refreshDelay = 10;
    _refreshTimer = Timer(Duration(seconds: refreshDelay), () async {
      await performTokenRefresh();
    });
  }

  Future<bool> performTokenRefresh() async {
    if (_offlineMode ||
        _refreshToken == null ||
        _isRefreshing ||
        _cachedSessionInvalid) {
      return false;
    }
    _isRefreshing = true;
    try {
      final client = await createTokenClient();
      final tokens = await client.refresh(refreshToken: _refreshToken!);
      saveTokens(tokens.$1, tokens.$2);
      AppLogger.info('Token refreshed automatically.');
      return true;
    } catch (e) {
      if (e is SdkError_Network) setOfflineMode(true);
      if (_isInvalidCachedTokenError(e)) {
        await _autoLogoutForExpiredSession();
        AppLogger.warning(
          'Session expired or was revoked; cached session data was cleared.',
        );
        return false;
      }
      AppLogger.error('Token refresh failed.', error: e);
      if (_refreshToken != null) _startRefreshTimer(30);
      return false;
    } finally {
      _isRefreshing = false;
    }
  }

  Future<void> logout() async {
    try {
      if (_accessToken != null) {
        final client = await createTokenClient();
        await client.logout(accessToken: _accessToken!);
      }
    } catch (e) {
      AppLogger.error('Server logout failed.', error: e);
    } finally {
      await clearAllCachedData();
    }
  }

  void clear() {
    _refreshTimer?.cancel();
    _cachedSessionInvalid = false;
    _accessToken = null;
    _refreshToken = null;
    unawaited(LocalVaultStorage.instance.clearTokens());
    unawaited(LocalVaultStorage.instance.clearCredentials());
  }

  Future<void> clearAllCachedData() async {
    _refreshTimer?.cancel();
    _cachedSessionInvalid = false;
    _accessToken = null;
    _refreshToken = null;
    await zeroizeActiveCryptoKey();
    await LocalVaultStorage.instance.clearAllCachedData();
  }

  Future<void> _autoLogoutForExpiredSession() async {
    if (_isAutoLoggingOut) return;
    _isAutoLoggingOut = true;
    _refreshTimer?.cancel();
    _accessToken = null;
    _refreshToken = null;
    _cachedSessionInvalid = true;
    _sessionExpired = true;
    try {
      await zeroizeActiveCryptoKey();
      await LocalVaultStorage.instance.clearAllCachedData();
      notifyListeners();
    } finally {
      _isAutoLoggingOut = false;
    }
  }

  bool _isInvalidCachedTokenError(Object error) {
    if (error is! SdkError_Server) return false;
    final code = error.code.toUpperCase();
    final text = '${error.code} ${error.text}'.toUpperCase();
    final authCode =
        code.startsWith('AUTH_') &&
        (code.contains('TOKEN') ||
            code.contains('SESSION') ||
            code.contains('UNAUTHORIZED'));
    final invalidText =
        (text.contains('TOKEN') || text.contains('SESSION')) &&
        (text.contains('INVALID') ||
            text.contains('EXPIRED') ||
            text.contains('REVOKED') ||
            text.contains('UNAUTHORIZED') ||
            text.contains('UNAUTHENTICATED'));
    return authCode || invalidText;
  }
}
