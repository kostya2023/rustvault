import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/auth_service.dart';

class DebugApiMenu extends StatefulWidget {
  final bool compact;
  final GlobalKey<NavigatorState> navigatorKey;
  final GlobalKey<ScaffoldMessengerState> scaffoldMessengerKey;

  const DebugApiMenu({
    super.key,
    required this.compact,
    required this.navigatorKey,
    required this.scaffoldMessengerKey,
  });

  @override
  State<DebugApiMenu> createState() => _DebugApiMenuState();
}

class _DebugApiMenuState extends State<DebugApiMenu> {
  Future<void> _showConfigDialog() async {
    final authService = AuthService();
    var url = authService.baseUrl;
    var selectedCert = authService.sslCaPinnedCert;
    var selectedCertPath = authService.sslCaPinnedCertPath;
    var useBuiltinCa =
        authService.sslCaPinnedCertPath == 'assets/certificates/ca.crt';

    final navigatorContext = widget.navigatorKey.currentState?.overlay?.context;
    if (navigatorContext == null) {
      throw StateError('Корневой Navigator ещё не готов.');
    }

    final saved = await showDialog<bool>(
      context: navigatorContext,
      builder: (dialogContext) => StatefulBuilder(
        builder: (dialogContext, setDialogState) => AlertDialog(
          backgroundColor: const Color(0xFF18181B),
          title: const Text(
            'Настройка API-сервера',
            style: TextStyle(fontSize: 16),
          ),
          scrollable: true,
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Этот адрес будет использоваться всеми запросами приложения.',
                style: TextStyle(fontSize: 13, color: Color(0xFFA1A1AA)),
              ),
              const SizedBox(height: 16),
              TextFormField(
                initialValue: url,
                onChanged: (value) => url = value,
                style: const TextStyle(color: Colors.white, fontSize: 14),
                decoration: const InputDecoration(
                  labelText: 'Base URL',
                  hintText: 'https://vault.example:8443',
                ),
              ),
              const SizedBox(height: 12),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                value: useBuiltinCa,
                onChanged: (enabled) async {
                  if (enabled != true) {
                    setDialogState(() {
                      useBuiltinCa = false;
                      selectedCert = null;
                      selectedCertPath = null;
                    });
                    return;
                  }

                  try {
                    final certificate = await rootBundle.load(
                      'assets/certificates/ca.crt',
                    );
                    setDialogState(() {
                      useBuiltinCa = true;
                      selectedCert = certificate.buffer.asUint8List(
                        certificate.offsetInBytes,
                        certificate.lengthInBytes,
                      );
                      selectedCertPath = 'assets/certificates/ca.crt';
                    });
                  } catch (error) {
                    setDialogState(() => useBuiltinCa = false);
                    widget.scaffoldMessengerKey.currentState?.showSnackBar(
                      SnackBar(
                        content: Text(
                          'Не удалось загрузить встроенный CA: $error',
                        ),
                      ),
                    );
                  }
                },
                title: const Text('Использовать встроенный CA Cert'),
                subtitle: const Text(
                  'Брать сертификат из assets/certificates/ca.crt',
                  style: TextStyle(fontSize: 12, color: Color(0xFFA1A1AA)),
                ),
                controlAffinity: ListTileControlAffinity.leading,
              ),
              const SizedBox(height: 4),
              OutlinedButton.icon(
                onPressed: () async {
                  try {
                    final result = await FilePicker.platform.pickFiles(
                      type: FileType.custom,
                      allowedExtensions: const ['pem', 'crt', 'cer', 'der'],
                      withData: true,
                    );
                    if (result == null) return;
                    final file = result.files.single;
                    final bytes = file.bytes;
                    if (bytes == null || bytes.isEmpty) {
                      throw StateError('Файл сертификата пуст или недоступен.');
                    }
                    setDialogState(() {
                      useBuiltinCa = false;
                      selectedCert = bytes;
                      selectedCertPath = file.name;
                    });
                  } catch (error) {
                    widget.scaffoldMessengerKey.currentState?.showSnackBar(
                      SnackBar(
                        content: Text('Не удалось прочитать CA: $error'),
                      ),
                    );
                  }
                },
                icon: const Icon(Icons.upload_file, size: 18),
                label: Text(
                  selectedCertPath == null
                      ? 'Выбрать SSL CA-сертификат'
                      : 'Сертификат: $selectedCertPath',
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (selectedCert != null)
                TextButton(
                  onPressed: () => setDialogState(() {
                    useBuiltinCa = false;
                    selectedCert = null;
                    selectedCertPath = null;
                  }),
                  child: const Text('Убрать CA-сертификат'),
                ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext, false),
              child: const Text('Отмена'),
            ),
            ElevatedButton(
              onPressed: () {
                final normalizedUrl = url.trim();
                final parsedUrl = Uri.tryParse(normalizedUrl);
                if (parsedUrl == null ||
                    !parsedUrl.hasAuthority ||
                    !const ['http', 'https'].contains(parsedUrl.scheme)) {
                  widget.scaffoldMessengerKey.currentState?.showSnackBar(
                    const SnackBar(
                      content: Text('Введите корректный HTTP(S) Base URL.'),
                    ),
                  );
                  return;
                }

                authService
                  ..baseUrl = normalizedUrl
                  ..setSslCaPinnedCert(selectedCert, path: selectedCertPath);
                Navigator.pop(dialogContext, true);
              },
              child: const Text('Сохранить'),
            ),
          ],
        ),
      ),
    );

    if (!mounted || saved != true) return;
    setState(() {});
    widget.scaffoldMessengerKey.currentState?.showSnackBar(
      SnackBar(
        content: Text('API настроен: ${authService.baseUrl}'),
        backgroundColor: const Color(0xFF10B981),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final apiUrl = AuthService().baseUrl;
    return FloatingActionButton.extended(
      onPressed: _showConfigDialog,
      backgroundColor: const Color(0xFF18181B),
      foregroundColor: const Color(0xFFA1A1AA),
      elevation: 2,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8),
        side: const BorderSide(color: Color(0xFF27272A)),
      ),
      icon: const Icon(Icons.bug_report, size: 16, color: Color(0xFF10B981)),
      label: Text(
        widget.compact ? 'Debug menu' : 'Debug menu · API: $apiUrl',
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(fontSize: 12),
      ),
    );
  }
}
