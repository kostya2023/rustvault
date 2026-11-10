import 'package:flutter/foundation.dart';

class MemoryProtectionService extends ChangeNotifier {
  static final MemoryProtectionService _instance =
      MemoryProtectionService._internal();
  factory MemoryProtectionService() => _instance;
  MemoryProtectionService._internal();

  bool _isLocked = false;
  bool get isLocked => _isLocked;

  void lock() {
    if (_isLocked) return;
    _isLocked = true;
    notifyListeners();
  }

  void unlock() {
    if (!_isLocked) return;
    _isLocked = false;
    notifyListeners();
  }
}
