import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:webauthn_secure_storage/webauthn_secure_storage.dart';

import 'rust/api/types/errors.dart';
import 'rust/api/types/master_key.dart';
import 'rust/api/types/security.dart';
import 'services/auth_service.dart';
import 'services/webauthn_options.dart';
import 'services/passkey_executor.dart';
import 'services/totp_code.dart';
import 'widgets/operation_stopwatch.dart';

class AccountManagementDialog extends StatefulWidget {
  final String username;
  final String accessToken;
  final CryptoKey? cryptoKey;
  final VoidCallback onAccountDeleted;

  const AccountManagementDialog({
    super.key,
    required this.username,
    required this.accessToken,
    required this.cryptoKey,
    required this.onAccountDeleted,
  });

  @override
  State<AccountManagementDialog> createState() =>
      _AccountManagementDialogState();
}

class _AccountManagementDialogState extends State<AccountManagementDialog> {
  List<PasskeyInfo> _passkeys = [];
  List<SecurityEvent> _events = [];
  bool _isLoading = true;
  bool _isLoadingMoreEvents = false;
  bool _isBusy = false;
  String? _busyStatus;
  String? _loadError;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<T> _withFreshToken<T>(Future<T> Function(String token) action) async {
    String? token = AuthService().accessToken ?? widget.accessToken;
    try {
      return await action(token);
    } on SdkError catch (error) {
      if (error is! SdkError_Server || error.code != 'AUTH_TOKEN_INVALID') {
        rethrow;
      }
      final refreshed = await AuthService().performTokenRefresh();
      token = AuthService().accessToken;
      if (!refreshed || token == null) rethrow;
      return action(token);
    }
  }

  Future<void> _loadData() async {
    if (mounted) {
      setState(() {
        _isLoading = true;
        _loadError = null;
      });
    }
    try {
      final securityClient = await AuthService().createSecurityClient();
      final passkeys = await _withFreshToken(
        (token) => securityClient.getPasskeys(accessToken: token),
      );
      final events = await _withFreshToken(
        (token) =>
            securityClient.getEvents(accessToken: token, limit: 50, offset: 0),
      );
      if (!mounted) return;
      setState(() {
        _passkeys = passkeys;
        _events = events;
        _isLoading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _loadError = error.toString();
        _isLoading = false;
      });
    }
  }

  void _showMessage(String message, {bool isError = false}) {
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

  Future<void> _registerPasskey() async {
    final name = await _askForPasskeyName();
    if (name == null || name.trim().isEmpty) return;

    setState(() {
      _isBusy = true;
      _busyStatus = 'Получение параметров регистрации Passkey…';
    });
    try {
      final client = await AuthService().createSecurityClient();
      final challenge = await _withFreshToken(
        (token) => client.addPasskeyStep1(accessToken: token),
      );
      final options = PublicKeyCredentialCreationOptionsJson.fromJson(
        parseWebAuthnPublicKeyOptions(challenge.passkeyPropsJson),
      );
      if (mounted) {
        setState(() => _busyStatus = 'Ожидание создания Passkey…');
      }
      final attestation = await registerPasskeyWithoutBlockingUi(options);
      if (mounted) {
        setState(() => _busyStatus = 'Сохранение Passkey на сервере…');
      }
      await _withFreshToken(
        (freshToken) => client.addPasskeyStep2(
          accessToken: freshToken,
          operationId: challenge.operationId,
          keyname: name.trim(),
          passkeyPropsJson: jsonEncode(attestation.toJson()),
        ),
      );
      await _loadData();
      _showMessage('Passkey «${name.trim()}» добавлен.');
    } catch (error) {
      _showMessage(
        'Не удалось зарегистрировать Passkey: $error',
        isError: true,
      );
    } finally {
      if (mounted) {
        setState(() {
          _isBusy = false;
          _busyStatus = null;
        });
      }
    }
  }

  Future<String?> _askForPasskeyName() {
    final controller = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: const Color(0xFF18181B),
        title: const Text('Название Passkey'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(hintText: 'Например, ноутбук'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Отмена'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, controller.text),
            child: const Text('Продолжить'),
          ),
        ],
      ),
    ).whenComplete(controller.dispose);
  }

  Future<void> _deletePasskey(PasskeyInfo passkey) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: const Color(0xFF18181B),
        title: const Text('Удалить Passkey?'),
        content: Text(
          'Ключ «${passkey.keyname}» больше нельзя будет использовать для входа.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Отмена'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Удалить'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    setState(() {
      _isBusy = true;
      _busyStatus = 'Удаление Passkey…';
    });
    try {
      final client = await AuthService().createSecurityClient();
      final challenge = await _withFreshToken(
        (token) => client.deletePasskeyStep1(
          accessToken: token,
          credentialId: passkey.credentialId,
        ),
      );
      await _withFreshToken(
        (token) => client.deletePasskeyStep2(
          accessToken: token,
          operationId: challenge.operationId,
          credentialId: challenge.credentialId,
          passkeyPropsJson: challenge.passkeyPropsJson,
        ),
      );
      await _loadData();
      _showMessage('Passkey «${passkey.keyname}» удалён.');
    } catch (error) {
      _showMessage('Не удалось удалить Passkey: $error', isError: true);
    } finally {
      if (mounted) {
        setState(() {
          _isBusy = false;
          _busyStatus = null;
        });
      }
    }
  }

  Future<void> _loadMoreEvents() async {
    if (_isLoadingMoreEvents || _events.length < 50) return;
    setState(() => _isLoadingMoreEvents = true);
    try {
      final client = await AuthService().createSecurityClient();
      final nextPage = await _withFreshToken(
        (token) => client.getEvents(
          accessToken: token,
          limit: 50,
          offset: _events.length,
        ),
      );
      if (mounted) {
        setState(() {
          final knownIds = _events.map((event) => event.id).toSet();
          _events.addAll(nextPage.where((event) => knownIds.add(event.id)));
        });
      }
    } catch (error) {
      _showMessage('Не удалось загрузить события: $error', isError: true);
    } finally {
      if (mounted) setState(() => _isLoadingMoreEvents = false);
    }
  }

  Future<void> _deleteAccount() async {
    final confirmation = await _confirmAccountDeletion();
    if (confirmation != true) return;
    final method = await _chooseAccountDeletionMethod();
    if (method == null) return;

    setState(() {
      _isBusy = true;
      _busyStatus = method == 'totp'
          ? 'Подготовка удаления через TOTP…'
          : 'Получение challenge Passkey…';
    });
    try {
      final accountClient = await AuthService().createAccountClient();
      if (method == 'totp') {
        final cryptoKey = widget.cryptoKey;
        if (cryptoKey == null) {
          throw StateError('Для удаления через TOTP войдите по паролю.');
        }
        if (mounted) {
          setState(() => _busyStatus = 'Проверка пароля аккаунта…');
        }
        final session = await _withFreshToken(
          (token) => accountClient.deleteWithPasstotpStep1(
            accessToken: token,
            cryptoKey: cryptoKey,
          ),
        );
        final totpCode = await _askForTotpCode();
        if (totpCode == null) {
          _showMessage('Удаление аккаунта отменено.');
          return;
        }
        await _withFreshToken(
          (token) => accountClient.deleteWithPasstotpStep2(
            accessToken: token,
            session: session,
            totpCode: totpCode,
          ),
        );
      } else {
        final challenge = await _withFreshToken(
          (token) => accountClient.deleteWithPasskeyStep1(accessToken: token),
        );
        final requestOptions = PublicKeyCredentialRequestOptionsJson.fromJson(
          parseWebAuthnPublicKeyOptions(challenge.passkeyPropsJson),
        );
        if (mounted) {
          setState(() => _busyStatus = 'Подтвердите удаление через Passkey…');
        }
        final assertion = await authenticatePasskeyWithoutBlockingUi(
          requestOptions,
        );
        await _withFreshToken(
          (token) => accountClient.deleteWithPasskeyStep2(
            accessToken: token,
            operationId: challenge.operationId,
            passkeyPropsJson: jsonEncode(assertion.toJson()),
          ),
        );
      }
      AuthService().clear();
      if (mounted) Navigator.pop(context);
      widget.onAccountDeleted();
    } catch (error) {
      _showMessage('Не удалось удалить аккаунт: $error', isError: true);
    } finally {
      if (mounted) {
        setState(() {
          _isBusy = false;
          _busyStatus = null;
        });
      }
    }
  }

  Future<String?> _chooseAccountDeletionMethod() {
    return showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: const Color(0xFF18181B),
        title: const Text('Подтвердите удаление'),
        content: const Text('Выберите способ подтверждения удаления аккаунта.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Отмена'),
          ),
          if (widget.cryptoKey != null)
            OutlinedButton.icon(
              onPressed: () => Navigator.pop(dialogContext, 'totp'),
              icon: const Icon(Icons.password),
              label: const Text('Пароль + TOTP'),
            ),
          FilledButton.icon(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.pop(dialogContext, 'passkey'),
            icon: const Icon(Icons.fingerprint),
            label: const Text('Passkey'),
          ),
        ],
      ),
    );
  }

  Future<bool?> _confirmAccountDeletion() {
    final controller = TextEditingController();
    return showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: const Color(0xFF18181B),
        title: const Text('Удалить аккаунт навсегда?'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Это действие необратимо и удалит аккаунт и его данные с сервера. Для подтверждения введите имя аккаунта:',
            ),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              decoration: const InputDecoration(labelText: 'Имя пользователя'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Отмена'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.pop(
              dialogContext,
              controller.text.trim() == widget.username,
            ),
            child: const Text('Удалить аккаунт'),
          ),
        ],
      ),
    ).whenComplete(controller.dispose);
  }

  Future<String?> _askForTotpCode() {
    final controller = TextEditingController();
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: const Color(0xFF18181B),
        title: const Text('Подтвердите удаление'),
        content: TextField(
          controller: controller,
          autofocus: true,
          keyboardType: TextInputType.number,
          inputFormatters: [FilteringTextInputFormatter.digitsOnly],
          maxLength: 8,
          decoration: const InputDecoration(labelText: 'Код TOTP'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Отмена'),
          ),
          FilledButton(
            onPressed: () {
              final code = controller.text.trim();
              if (isValidTotpCode(code)) {
                Navigator.pop(dialogContext, code);
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Код TOTP должен содержать ровно 8 цифр.'),
                  ),
                );
              }
            },
            child: const Text('Подтвердить'),
          ),
        ],
      ),
    ).whenComplete(controller.dispose);
  }

  String _shortCredentialId(String credentialId) => credentialId.length <= 16
      ? credentialId
      : '${credentialId.substring(0, 16)}…';

  String _eventTypeName(String code) {
    const names = {
      'LOGIN_SUCCESS': 'УспешныйВход',
      'LOGIN_FAILED': 'НеудачнаяПопыткаВхода',
      'LOGIN': 'ВходВАккаунт',
      'LOGOUT': 'ВыходИзАккаунта',
      'PASSKEY_LOGIN': 'ВходПоPasskey',
      'PASSKEY_ADDED': 'ДобавленPasskey',
      'PASSKEY_REGISTERED': 'ЗарегистрированPasskey',
      'PASSKEY_DELETED': 'УдалёнPasskey',
      'PASSWORD_CHANGED': 'ИзменёнПароль',
      'TOTP_ENABLED': 'ВключенаДвухфакторнаяАутентификация',
      'TOTP_DISABLED': 'ОтключенаДвухфакторнаяАутентификация',
      'ACCOUNT_CREATED': 'СозданАккаунт',
      'ACCOUNT_DELETED': 'УдалёнАккаунт',
      'TOKEN_REFRESHED': 'ОбновленаСессия',
    };
    final normalized = code.trim().toUpperCase();
    final knownName = names[normalized];
    if (knownName != null) return knownName;

    final words = code
        .trim()
        .replaceAll(RegExp(r'[_-]+'), ' ')
        .split(RegExp(r'\s+'))
        .where((word) => word.isNotEmpty)
        .map(
          (word) =>
              '${word[0].toUpperCase()}${word.substring(1).toLowerCase()}',
        );
    final readable = words.join();
    return readable.isEmpty ? 'СобытиеАккаунта' : readable;
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: const Color(0xFF14141A),
      child: SizedBox(
        width: 540,
        height: MediaQuery.sizeOf(context).height * 0.82,
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  const Icon(Icons.manage_accounts, color: Color(0xFF60A5FA)),
                  const SizedBox(width: 10),
                  const Expanded(
                    child: Text(
                      'Управление аккаунтом',
                      style: TextStyle(
                        fontSize: 19,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  IconButton(
                    tooltip: 'Обновить',
                    onPressed: _isLoading || _isBusy ? null : _loadData,
                    icon: const Icon(Icons.refresh),
                  ),
                  if (_isLoading || _isLoadingMoreEvents) ...[
                    const SizedBox(width: 8),
                    const OperationStopwatch(running: true),
                  ],
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close),
                  ),
                ],
              ),
              const Divider(color: Color(0xFF27272A)),
              if (_isLoading)
                const Expanded(
                  child: Center(child: CircularProgressIndicator()),
                )
              else if (_loadError != null)
                Expanded(
                  child: Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          'Не удалось загрузить данные аккаунта:\n$_loadError',
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 12),
                        FilledButton(
                          onPressed: _loadData,
                          child: const Text('Повторить'),
                        ),
                      ],
                    ),
                  ),
                )
              else
                Expanded(
                  child: SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Row(
                          children: [
                            const Expanded(
                              child: Text(
                                'Passkeys',
                                style: TextStyle(
                                  fontSize: 16,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                            TextButton.icon(
                              onPressed: _isBusy ? null : _registerPasskey,
                              icon: const Icon(Icons.add, size: 18),
                              label: const Text('Добавить'),
                            ),
                          ],
                        ),
                        if (_passkeys.isEmpty)
                          const _EmptySection('Passkey ещё не добавлены.')
                        else
                          ..._passkeys.map(
                            (passkey) => _PasskeyTile(
                              passkey: passkey,
                              credentialShort: _shortCredentialId(
                                passkey.credentialId,
                              ),
                              onDelete: _isBusy
                                  ? null
                                  : () => _deletePasskey(passkey),
                            ),
                          ),
                        const SizedBox(height: 18),
                        Row(
                          children: [
                            const Expanded(
                              child: Text(
                                'История событий',
                                style: TextStyle(
                                  fontSize: 16,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                            Text(
                              '${_events.length}',
                              style: const TextStyle(color: Color(0xFF94A3B8)),
                            ),
                          ],
                        ),
                        if (_events.isEmpty)
                          const _EmptySection('Событий нет.')
                        else
                          ..._events.map(
                            (event) => _EventTile(
                              event: event,
                              title: _eventTypeName(event.eventType),
                            ),
                          ),
                        if (_events.length >= 50)
                          Align(
                            alignment: Alignment.center,
                            child: TextButton(
                              onPressed: _isLoadingMoreEvents
                                  ? null
                                  : _loadMoreEvents,
                              child: _isLoadingMoreEvents
                                  ? const SizedBox(
                                      width: 18,
                                      height: 18,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                      ),
                                    )
                                  : const Text('Загрузить ещё события'),
                            ),
                          ),
                      ],
                    ),
                  ),
                ),
              if (_isBusy) ...[
                Row(
                  children: [
                    const Expanded(child: LinearProgressIndicator()),
                    const SizedBox(width: 10),
                    const OperationStopwatch(running: true),
                  ],
                ),
                if (_busyStatus != null) ...[
                  const SizedBox(height: 8),
                  Text(
                    _busyStatus!,
                    style: const TextStyle(
                      color: Color(0xFF94A3B8),
                      fontSize: 12,
                    ),
                  ),
                ],
              ],
              const Divider(color: Color(0xFF27272A)),
              Align(
                alignment: Alignment.centerRight,
                child: TextButton.icon(
                  onPressed: _isBusy ? null : _deleteAccount,
                  icon: const Icon(Icons.delete_forever, color: Colors.red),
                  label: const Text(
                    'Удалить аккаунт',
                    style: TextStyle(color: Colors.red),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _EmptySection extends StatelessWidget {
  final String text;

  const _EmptySection(this.text);

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 14),
    child: Text(text, style: const TextStyle(color: Color(0xFF71717A))),
  );
}

class _PasskeyTile extends StatelessWidget {
  final PasskeyInfo passkey;
  final String credentialShort;
  final VoidCallback? onDelete;

  const _PasskeyTile({
    required this.passkey,
    required this.credentialShort,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) => Card(
    color: const Color(0xFF1C1C24),
    child: ListTile(
      title: Text(
        passkey.keyname.isEmpty ? 'Passkey' : passkey.keyname,
        style: const TextStyle(fontWeight: FontWeight.w600),
      ),
      subtitle: Text(
        '$credentialShort\nДобавлен: ${passkey.createdAt}',
        style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
      ),
      isThreeLine: true,
      trailing: IconButton(
        tooltip: 'Удалить Passkey',
        onPressed: onDelete,
        icon: const Icon(Icons.delete_outline, color: Color(0xFFEF4444)),
      ),
    ),
  );
}

class _EventTile extends StatelessWidget {
  final SecurityEvent event;
  final String title;

  const _EventTile({required this.event, required this.title});

  @override
  Widget build(BuildContext context) => Card(
    color: const Color(0xFF1C1C24),
    child: ListTile(
      title: Text(title),
      subtitle: Text(
        [
          if (event.eventText?.isNotEmpty == true) event.eventText!,
          event.createdAt,
          if (event.ipAddress?.isNotEmpty == true) event.ipAddress!,
          if (event.userAgent?.isNotEmpty == true) event.userAgent!,
        ].join(' · '),
        style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
      ),
    ),
  );
}
