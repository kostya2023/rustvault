import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';

extension on Uint8List {
  void zeroize() => fillRange(0, length, 0);
}

/// Device-local state. Secrets are kept in the platform keychain/keystore;
/// the encrypted vault envelope is kept in the OS temp directory only.
class LocalVaultStorage {
  LocalVaultStorage._();

  static final LocalVaultStorage instance = LocalVaultStorage._();
  static const _tokensKey = 'rustvault.auth.tokens.v1';
  static const _credentialsKey = 'rustvault.cached.credentials.v1';

  final FlutterSecureStorage _secure = const FlutterSecureStorage();

  Future<void> saveTokens(String accessToken, String refreshToken) async {
    await _secure.write(
      key: _tokensKey,
      value: jsonEncode({'access': accessToken, 'refresh': refreshToken}),
    );
  }

  Future<(String, String)?> readTokens() async {
    final raw = await _secure.read(key: _tokensKey);
    if (raw == null) return null;
    try {
      final json = jsonDecode(raw) as Map<String, dynamic>;
      final access = json['access'] as String?;
      final refresh = json['refresh'] as String?;
      if (access == null ||
          refresh == null ||
          access.isEmpty ||
          refresh.isEmpty) {
        return null;
      }
      return (access, refresh);
    } catch (_) {
      await clearTokens();
      return null;
    }
  }

  Future<void> clearTokens() => _secure.delete(key: _tokensKey);

  Future<void> saveCredentials({
    required String username,
    required String password,
  }) => _secure.write(
    key: _credentialsKey,
    value: jsonEncode({'username': username, 'password': password}),
  );

  Future<(String, String)?> readCredentials() async {
    final raw = await _secure.read(key: _credentialsKey);
    if (raw == null) return null;
    try {
      final json = jsonDecode(raw) as Map<String, dynamic>;
      final username = json['username'] as String?;
      final password = json['password'] as String?;
      if (username == null || password == null) return null;
      return (username, password);
    } catch (_) {
      await clearCredentials();
      return null;
    }
  }

  Future<void> clearCredentials() => _secure.delete(key: _credentialsKey);

  Future<File> _blobFile() async {
    final directory = await getTemporaryDirectory();
    return File('${directory.path}${Platform.pathSeparator}rustvault.blob');
  }

  Future<File> _blobMetadataFile() async {
    final blob = await _blobFile();
    return File('${blob.path}.meta');
  }

  Future<void> saveBlob(Uint8List bytes, {int? version}) async {
    final file = await _blobFile();
    final temporary = File('${file.path}.new');
    await temporary.writeAsBytes(bytes, flush: true);
    if (await file.exists()) await file.delete();
    await temporary.rename(file.path);
    if (version != null) {
      final metadata = await _blobMetadataFile();
      await metadata.writeAsString('$version', flush: true);
    }
  }

  Future<Uint8List?> readBlob() async {
    final file = await _blobFile();
    if (!await file.exists()) return null;
    return file.readAsBytes();
  }

  Future<int> readBlobVersion() async {
    final metadata = await _blobMetadataFile();
    if (!await metadata.exists()) return 0;
    return int.tryParse(await metadata.readAsString()) ?? 0;
  }

  Future<void> clearBlob() async {
    final file = await _blobFile();
    await _zeroizeFile(file);
    final metadata = await _blobMetadataFile();
    await _zeroizeFile(metadata);
  }

  Future<void> _zeroizeFile(File file) async {
    if (!await file.exists()) return;

    final bytes = await file.readAsBytes();
    try {
      bytes.zeroize();
      await file.writeAsBytes(bytes, flush: true);
    } finally {
      bytes.zeroize();
    }
    await file.delete();
  }

  /// Removes all authentication and vault data cached on this device.
  /// The window preference is intentionally preserved.
  Future<void> clearAllCachedData() async {
    await Future.wait([clearTokens(), clearCredentials(), clearBlob()]);
  }
}
