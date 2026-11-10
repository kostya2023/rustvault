import 'dart:async';

import '../rust/api/clients/auth_client.dart';

class AuthService {
  static final AuthService _instance = AuthService._internal();
  factory AuthService() => AuthService._internal();
  AuthService._internal();

  String? _accessToken;
  String? _refreshToken;
  Timer? _refreshTimer;

  String _baseUrl = 'http://localhost:80';

  String? get accessToken => _accessToken;
  String? get refreshToken => _refreshToken;
  String get baseUrl => _baseUrl;

  set baseUrl(String value) {
    _baseUrl = value;
  }

  void saveTokens(
    String accessToken,
    String refreshToken, {
    String? currentBaseUrl,
    int expiresInSeconds = 900,
  }) {
    _accessToken = accessToken;
    _refreshToken = refreshToken;

    if (currentBaseUrl != null) {
      _baseUrl = currentBaseUrl;
    }

    _startRefreshTimer(expiresInSeconds);
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
    if (_refreshToken == null) return false;

    try {
      final client = await TokenClient.withBaseUrl(baseUrl: _baseUrl);
      final tokens = await client.refresh(refreshToken: _refreshToken!);

      saveTokens(tokens.$1, tokens.$2);
      print('✅ Токен успешно обновлен автоматически.');
      return true;
    } catch (e) {
      print('❌ Ошибка при автообновлении токена: $e');
      return false;
    }
  }

  Future<void> logout() async {
    try {
      if (_accessToken != null) {
        final client = await TokenClient.withBaseUrl(baseUrl: _baseUrl);
        await client.logout(accessToken: _accessToken!);
      }
    } catch (e) {
      print('❌ Ошибка при выходе на сервере: $e');
    } finally {
      clear();
    }
  }

  void clear() {
    _refreshTimer?.cancel();
    _accessToken = null;
    _refreshToken = null;
  }
}
