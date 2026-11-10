import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:webauthn_secure_storage/webauthn_secure_storage.dart';
import 'package:webauthn_secure_storage_windows/webauthn_secure_storage_windows.dart';

Future<PublicKeyCredentialAssertionJson> authenticatePasskeyWithoutBlockingUi(
  PublicKeyCredentialRequestOptionsJson options,
) async {
  if (!Platform.isWindows) {
    return BiometricStorage().authenticateWithPasskey(options);
  }

  final responseJson = await Isolate.run(() async {
    try {
      final platform = BiometricStorageWindows();
      final requestOptions = PublicKeyCredentialRequestOptionsJson.fromJson(
        Map<String, dynamic>.from(
          jsonDecode(jsonEncode(options.toJson())) as Map,
        ),
      );
      final assertion = await platform.authenticateWithPasskey(requestOptions);
      return jsonEncode(<String, Object?>{
        'ok': true,
        'response': assertion.toJson(),
      });
    } catch (error) {
      return jsonEncode(<String, Object?>{
        'ok': false,
        'error': error.toString(),
      });
    }
  });

  final result = Map<String, dynamic>.from(jsonDecode(responseJson) as Map);
  if (result['ok'] != true) {
    throw StateError('Passkey authentication failed: ${result['error']}');
  }
  return PublicKeyCredentialAssertionJson.fromJson(
    Map<String, dynamic>.from(result['response'] as Map),
  );
}

Future<PublicKeyCredentialAttestationJson> registerPasskeyWithoutBlockingUi(
  PublicKeyCredentialCreationOptionsJson options,
) async {
  if (!Platform.isWindows) {
    return BiometricStorage().registerPasskey(options);
  }

  final responseJson = await Isolate.run(() async {
    try {
      final platform = BiometricStorageWindows();
      final creationOptions = PublicKeyCredentialCreationOptionsJson.fromJson(
        Map<String, dynamic>.from(
          jsonDecode(jsonEncode(options.toJson())) as Map,
        ),
      );
      final attestation = await platform.registerPasskey(creationOptions);
      return jsonEncode(<String, Object?>{
        'ok': true,
        'response': attestation.toJson(),
      });
    } catch (error) {
      return jsonEncode(<String, Object?>{
        'ok': false,
        'error': error.toString(),
      });
    }
  });

  final result = Map<String, dynamic>.from(jsonDecode(responseJson) as Map);
  if (result['ok'] != true) {
    throw StateError('Passkey registration failed: ${result['error']}');
  }
  return PublicKeyCredentialAttestationJson.fromJson(
    Map<String, dynamic>.from(result['response'] as Map),
  );
}
