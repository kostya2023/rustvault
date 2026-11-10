import 'package:webauthn_secure_storage/webauthn_secure_storage.dart';

Future<PublicKeyCredentialAssertionJson> authenticatePasskeyWithoutBlockingUi(
  PublicKeyCredentialRequestOptionsJson options,
) => BiometricStorage().authenticateWithPasskey(options);

Future<PublicKeyCredentialAttestationJson> registerPasskeyWithoutBlockingUi(
  PublicKeyCredentialCreationOptionsJson options,
) => BiometricStorage().registerPasskey(options);
