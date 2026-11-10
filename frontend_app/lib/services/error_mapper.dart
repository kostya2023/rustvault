import '../rust/api/types/errors.dart';

String describeAppErrorForLog(Object error) {
  if (error is SdkError_Network) return 'Network connection unavailable';
  if (error is SdkError_Internal) return 'Internal client error';
  if (error is SdkError_Crypto) return 'Cryptographic operation failed';
  if (error is SdkError_Server) {
    switch (error.code) {
      case 'AUTH_TOKEN_INVALID':
      case 'AUTH_REFRESH_TOKEN_INVALID':
      case 'AUTH_REFRESH_TOKEN_EXPIRED':
      case 'AUTH_REFRESH_TOKEN_REVOKED':
        return 'Session expired or revoked';
      case 'BLOB_VERSION_NOT_INCREASING':
      case 'BLOB_VERSION_INVALID':
        return 'Vault version is stale';
      case 'BLOB_NOT_FOUND':
        return 'Encrypted vault was not found';
      case 'INVALID_CREDENTIALS':
      case 'AUTHENTICATION_FAILED':
        return 'Server rejected authentication';
      case 'PASSKEY_INVALID':
      case 'PASSKEY_VERIFICATION_FAILED':
        return 'Passkey verification failed';
      default:
        return 'Server rejected operation (code ${error.code})';
    }
  }
  return 'Unknown application error';
}

String describeAppError(Object error) {
  if (error is SdkError_Network) return 'Сетевое соединение недоступно';
  if (error is SdkError_Internal) return 'Внутренняя ошибка клиента';
  if (error is SdkError_Crypto) return 'Ошибка шифрования или расшифровки';
  if (error is SdkError_Server) {
    switch (error.code) {
      case 'AUTH_TOKEN_INVALID':
      case 'AUTH_REFRESH_TOKEN_INVALID':
      case 'AUTH_REFRESH_TOKEN_EXPIRED':
      case 'AUTH_REFRESH_TOKEN_REVOKED':
        return 'Сессия истекла или была отозвана';
      case 'BLOB_VERSION_NOT_INCREASING':
      case 'BLOB_VERSION_INVALID':
        return 'Версия хранилища устарела';
      case 'BLOB_NOT_FOUND':
        return 'Зашифрованное хранилище ещё не создано';
      case 'INVALID_CREDENTIALS':
      case 'AUTHENTICATION_FAILED':
        return 'Учетные данные отклонены сервером';
      case 'PASSKEY_INVALID':
      case 'PASSKEY_VERIFICATION_FAILED':
        return 'Проверка Passkey не пройдена';
      default:
        return 'Сервер отклонил операцию (код ${error.code})';
    }
  }
  return 'Неизвестная ошибка';
}
