import 'dart:convert';

Map<String, dynamic> parseWebAuthnPublicKeyOptions(String json) {
  final decoded = jsonDecode(json);
  if (decoded is! Map) {
    throw const FormatException('WebAuthn challenge must be a JSON object.');
  }

  final response = Map<String, dynamic>.from(decoded);
  final publicKey = response['publicKey'];
  if (publicKey == null) return response;
  if (publicKey is! Map) {
    throw const FormatException(
      'WebAuthn challenge publicKey must be a JSON object.',
    );
  }
  return Map<String, dynamic>.from(publicKey);
}
