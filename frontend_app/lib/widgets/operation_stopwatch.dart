import 'dart:async';

import 'package:flutter/material.dart';

class OperationStopwatch extends StatefulWidget {
  final bool running;

  const OperationStopwatch({super.key, required this.running});

  @override
  State<OperationStopwatch> createState() => _OperationStopwatchState();
}

class _OperationStopwatchState extends State<OperationStopwatch> {
  final Stopwatch _stopwatch = Stopwatch();
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    _updateTicker();
  }

  @override
  void didUpdateWidget(covariant OperationStopwatch oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.running != widget.running) _updateTicker();
  }

  void _updateTicker() {
    _ticker?.cancel();
    if (widget.running) {
      _stopwatch
        ..reset()
        ..start();
      _ticker = Timer.periodic(const Duration(milliseconds: 37), (_) {
        if (mounted) setState(() {});
      });
    } else {
      _stopwatch.stop();
      _stopwatch.reset();
    }
  }

  @override
  void dispose() {
    _ticker?.cancel();
    _stopwatch.stop();
    super.dispose();
  }

  String _formatElapsed(Duration elapsed) {
    final minutes = elapsed.inMinutes.toString().padLeft(2, '0');
    final seconds = (elapsed.inSeconds % 60).toString().padLeft(2, '0');
    final milliseconds = (elapsed.inMilliseconds % 1000).toString().padLeft(
      3,
      '0',
    );
    return '$minutes:$seconds.$milliseconds';
  }

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
    decoration: BoxDecoration(
      color: const Color(0xFF0B1220),
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: const Color(0xFF1E3A5F)),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(Icons.timer_outlined, size: 14, color: Color(0xFF60A5FA)),
        const SizedBox(width: 5),
        Text(
          _formatElapsed(_stopwatch.elapsed),
          style: const TextStyle(
            color: Color(0xFFBFDBFE),
            fontSize: 11,
            fontFeatures: [FontFeature.tabularFigures()],
            fontFamily: 'monospace',
          ),
        ),
      ],
    ),
  );
}
