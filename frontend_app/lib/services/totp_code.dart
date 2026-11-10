bool isValidTotpCode(String code) => RegExp(r'^\d{8}$').hasMatch(code);
