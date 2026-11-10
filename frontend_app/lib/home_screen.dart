import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'services/auth_service.dart';
import 'main.dart';
import 'rust/api/clients/vault_client.dart';
import 'rust/api/clients/crypto_client.dart';
import 'rust/api/types/master_key.dart';
import 'rust/api/types/blob.dart';
import 'rust/api/types/crypto.dart' as rust_crypto;

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

  // В FRB 2.13 PlatformInt64 на Dart-стороне является обычным int.
  int _currentVaultVersion = 1;

  late List<bool> _showPasswordList;
  bool _isLoggingOut = false;
  final ScrollController _scrollController = ScrollController();

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

  // 📥 Загрузка и расшифровка хранилища с сервера.
  Future<void> _loadVaultFromBackend() async {
    final cryptoKey = widget.cryptoKey;

    if (cryptoKey == null) {
      if (mounted) {
        setState(() => _isLoadingVault = false);
      }
      return;
    }

    try {
      final accessToken = AuthService().accessToken ?? widget.accessToken;
      final baseUrl = AuthService().baseUrl;

      if (accessToken == null) {
        if (mounted) {
          setState(() => _isLoadingVault = false);
        }
        return;
      }

      final vaultClient = await VaultClient.withBaseUrl(baseUrl: baseUrl);
      final cryptoClient = await CryptoClient.newInstance();

      // Получаем текущую версию хранилища.
      // Если метаданные ещё не существуют, начинаем с первой версии.
      try {
        final metadata = await vaultClient.getMetadata(
          accessToken: accessToken,
        );
        _currentVaultVersion = metadata.version;
      } catch (error) {
        _currentVaultVersion = 1;
        debugPrint('Не удалось получить метаданные хранилища: $error');
      }

      final Blob blob = await vaultClient.download(accessToken: accessToken);

      // decryptKeys возвращает Keys напрямую и не требует ручной работы с TbsBlob.
      final rust_crypto.Keys keys = await cryptoClient.decryptKeys(
        cryptoKey: cryptoKey,
        blob: blob,
      );

      if (!mounted) return;

      setState(() {
        _passwords = keys.keys
            .map((key) => PasswordItem.fromRustKey(key))
            .toList();
        _updatePasswordListState();
        _isLoadingVault = false;
      });
    } catch (error, stackTrace) {
      debugPrint('Ошибка загрузки/расшифровки хранилища: $error');
      debugPrintStack(stackTrace: stackTrace);

      if (!mounted) return;

      setState(() {
        _passwords = [];
        _updatePasswordListState();
        _isLoadingVault = false;
      });
    }
  }

  // 📤 Шифрование и отправка хранилища на сервер.
  Future<void> _saveVaultToBackend() async {
    final cryptoKey = widget.cryptoKey;

    if (cryptoKey == null) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('⚠️ Нет криптографического ключа сессии'),
          backgroundColor: Color(0xFFEF4444),
        ),
      );
      return;
    }

    if (mounted) {
      setState(() => _isSavingVault = true);
    }

    try {
      final accessToken = AuthService().accessToken ?? widget.accessToken;
      final baseUrl = AuthService().baseUrl;

      if (accessToken == null) {
        throw StateError('Нет access token. Войдите в аккаунт ещё раз.');
      }

      final vaultClient = await VaultClient.withBaseUrl(baseUrl: baseUrl);
      final cryptoClient = await CryptoClient.newInstance();

      final rust_crypto.Keys keys = rust_crypto.Keys(
        keys: _passwords.map((item) => item.toRustKey()).toList(),
      );

      // encryptKeys сам формирует TbsBlob/BlobHandler внутри Rust.
      // Не создаём BlobHandler с нулевой солью вручную.
      final Blob newBlob = await cryptoClient.encryptKeys(
        cryptoKey: cryptoKey,
        keys: keys,
      );

      await vaultClient.upload(
        accessToken: accessToken,
        blob: newBlob,
        version: _currentVaultVersion,
      );

      _currentVaultVersion += 1;

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('💾 Хранилище успешно синхронизировано с бэкендом!'),
            backgroundColor: Color(0xFF10B981),
          ),
        );
      }
    } catch (error, stackTrace) {
      debugPrint('Ошибка сохранения хранилища: $error');
      debugPrintStack(stackTrace: stackTrace);

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('❌ Ошибка сохранения в хранилище: $error'),
            backgroundColor: const Color(0xFFEF4444),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isSavingVault = false);
      }
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
                      ),
                    );
                    _updatePasswordListState();
                  });
                  Navigator.pop(dialogContext);
                  _saveVaultToBackend();
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
                  );
                });
                Navigator.pop(dialogContext);
                _saveVaultToBackend();
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

  void _deletePassword(int index) {
    setState(() {
      _passwords.removeAt(index);
      _updatePasswordListState();
    });
    _saveVaultToBackend();
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
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text(
                          '🔐 Мои пароли',
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: Color(0xFFFAFAFA),
                          ),
                        ),
                        ElevatedButton.icon(
                          onPressed: widget.cryptoKey == null
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
                      child: _isLoadingVault
                          ? const Center(
                              child: CircularProgressIndicator(
                                color: Color(0xFF3B82F6),
                              ),
                            )
                          : _passwords.isEmpty
                          ? Center(
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  const Icon(
                                    Icons.lock_open,
                                    size: 44,
                                    color: Color(0xFF334155),
                                  ),
                                  const SizedBox(height: 10),
                                  Text(
                                    widget.cryptoKey == null
                                        ? 'Вход по Passkey: расшифровка хранилища в разработке'
                                        : 'Список паролей пуст',
                                    style: const TextStyle(
                                      color: Color(0xFF94A3B8),
                                      fontSize: 14,
                                    ),
                                    textAlign: TextAlign.center,
                                  ),
                                ],
                              ),
                            )
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
