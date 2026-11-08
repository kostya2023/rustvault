import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:frontend_app/rust/api/types/master_key.dart';
import 'package:frontend_app/rust/frb_generated.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await RustLib.init();

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'RustVault',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MasterKeyPage(),
    );
  }
}

class MasterKeyPage extends StatefulWidget {
  const MasterKeyPage({super.key});

  @override
  State<MasterKeyPage> createState() => _MasterKeyPageState();
}

class _MasterKeyPageState extends State<MasterKeyPage> {
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();

  bool _isLoading = false;
  bool _obscurePassword = true;

  String? _fingerprint;
  String? _error;
  Duration? _elapsed;

  Future<void> _createMasterKey() async {
    final username = _usernameController.text;
    final password = _passwordController.text;

    if (username.isEmpty || password.isEmpty) {
      setState(() {
        _error = 'Username and password are required.';
        _fingerprint = null;
        _elapsed = null;
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _fingerprint = null;
      _error = null;
      _elapsed = null;
    });

    final stopwatch = Stopwatch()..start();

    MasterKey? masterKey;

    try {
      masterKey = await MasterKey.newInstance(
        username: utf8.encode(username),
        password: utf8.encode(password),
      );

      final fingerprint = await masterKey.fingerprint();

      stopwatch.stop();

      if (!mounted) return;

      setState(() {
        _fingerprint = fingerprint;
        _elapsed = stopwatch.elapsed;
      });
    } catch (e) {
      stopwatch.stop();

      if (!mounted) return;

      setState(() {
        _error = e.toString();
        _elapsed = stopwatch.elapsed;
      });
    } finally {
      if (masterKey != null) {
        try {
          await masterKey.zeroize();
        } catch (_) {
          // Ignore zeroization errors during cleanup.
        }
      }

      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _usernameController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('RustVault MasterKey'),
        centerTitle: true,
      ),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.lock_outline_rounded, size: 80),

                const SizedBox(height: 16),

                Text(
                  'MasterKey Generator',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),

                const SizedBox(height: 8),

                Text(
                  'Generate your RustVault MasterKey using Argon2id.',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),

                const SizedBox(height: 32),

                TextField(
                  controller: _usernameController,
                  enabled: !_isLoading,
                  textInputAction: TextInputAction.next,
                  decoration: const InputDecoration(
                    labelText: 'Username',
                    prefixIcon: Icon(Icons.person_outline),
                    border: OutlineInputBorder(),
                  ),
                ),

                const SizedBox(height: 16),

                TextField(
                  controller: _passwordController,
                  enabled: !_isLoading,
                  obscureText: _obscurePassword,
                  textInputAction: TextInputAction.done,
                  onSubmitted: (_) {
                    if (!_isLoading) {
                      _createMasterKey();
                    }
                  },
                  decoration: InputDecoration(
                    labelText: 'Password',
                    prefixIcon: const Icon(Icons.password_outlined),
                    border: const OutlineInputBorder(),
                    suffixIcon: IconButton(
                      onPressed: () {
                        setState(() {
                          _obscurePassword = !_obscurePassword;
                        });
                      },
                      icon: Icon(
                        _obscurePassword
                            ? Icons.visibility_outlined
                            : Icons.visibility_off_outlined,
                      ),
                    ),
                  ),
                ),

                const SizedBox(height: 24),

                SizedBox(
                  height: 52,
                  child: FilledButton(
                    onPressed: _isLoading ? null : _createMasterKey,
                    child: _isLoading
                        ? const SizedBox(
                            width: 24,
                            height: 24,
                            child: CircularProgressIndicator(strokeWidth: 2.5),
                          )
                        : const Text(
                            'Create MasterKey',
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                  ),
                ),

                if (_elapsed != null) ...[
                  const SizedBox(height: 24),

                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        children: [
                          const Icon(Icons.timer_outlined, size: 32),

                          const SizedBox(height: 8),

                          Text(
                            'Execution time',
                            style: theme.textTheme.titleMedium,
                          ),

                          const SizedBox(height: 4),

                          Text(
                            '${_elapsed!.inMicroseconds / 1000} ms',
                            style: theme.textTheme.headlineSmall?.copyWith(
                              fontWeight: FontWeight.bold,
                              fontFamily: 'monospace',
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],

                if (_fingerprint != null) ...[
                  const SizedBox(height: 16),

                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              const Icon(Icons.fingerprint, size: 28),
                              const SizedBox(width: 8),
                              Text(
                                'MasterKey Fingerprint',
                                style: theme.textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ],
                          ),

                          const SizedBox(height: 16),

                          SelectableText(
                            _fingerprint!,
                            style: const TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 16,
                              letterSpacing: 1.2,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],

                if (_error != null) ...[
                  const SizedBox(height: 16),

                  Card(
                    color: theme.colorScheme.errorContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Icon(
                            Icons.error_outline,
                            color: theme.colorScheme.onErrorContainer,
                          ),

                          const SizedBox(width: 12),

                          Expanded(
                            child: Text(
                              _error!,
                              style: TextStyle(
                                color: theme.colorScheme.onErrorContainer,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
