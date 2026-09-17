import 'dart:async';
import 'dart:math';
import 'package:flutter/material.dart';
import '../../../../data/models/threat_assessment.dart';
import '../../../../data/services/api_service.dart';

class DashboardViewModel extends ChangeNotifier {
  final ApiService _apiService;
  Timer? _pollingTimer;

  bool _isMonitoring = false;
  bool get isMonitoring => _isMonitoring;

  bool _hasConsent = false;
  bool get hasConsent => _hasConsent;

  bool _isConnectedToServer = false;
  bool get isConnectedToServer => _isConnectedToServer;

  String _serverUrl = 'http://192.168.1.100:5000';
  String get serverUrl => _serverUrl;

  int _totalFlowsScanned = 1248;
  int get totalFlowsScanned => _totalFlowsScanned;

  int _threatsDetected = 14;
  int get threatsDetected => _threatsDetected;

  ThreatAssessment _latestAssessment = ThreatAssessment.mock(type: 'BENIGN', risk: 18.2);
  ThreatAssessment get latestAssessment => _latestAssessment;

  final List<ThreatAssessment> _alertsHistory = [
    ThreatAssessment.mock(type: 'DDoS', risk: 94.6),
    ThreatAssessment.mock(type: 'PortScan', risk: 82.1),
    ThreatAssessment.mock(type: 'Novel Zero-Day', risk: 78.4),
  ];
  List<ThreatAssessment> get alertsHistory => List.unmodifiable(_alertsHistory);

  DashboardViewModel({ApiService? apiService})
      : _apiService = apiService ?? ApiService() {
    _checkServer();
  }

  void grantConsent(bool value) {
    _hasConsent = value;
    if (!_hasConsent && _isMonitoring) {
      toggleMonitoring(false);
    }
    notifyListeners();
  }

  void toggleMonitoring(bool value) {
    if (value && !_hasConsent) return;
    _isMonitoring = value;
    if (_isMonitoring) {
      _startLiveInspection();
    } else {
      _stopLiveInspection();
    }
    notifyListeners();
  }

  void updateServerUrl(String url) {
    _serverUrl = url;
    _apiService.updateBaseUrl(url);
    _checkServer();
    notifyListeners();
  }

  Future<void> _checkServer() async {
    _isConnectedToServer = await _apiService.checkHealth();
    notifyListeners();
  }

  void _startLiveInspection() {
    _pollingTimer?.cancel();
    _pollingTimer = Timer.periodic(const Duration(seconds: 3), (timer) {
      _totalFlowsScanned += Random().nextInt(5) + 1;
      
      // 90% benign, 10% occasional anomaly during auto-inspection
      final isAnomaly = Random().nextDouble() < 0.12;
      final risk = isAnomaly ? (65.0 + Random().nextDouble() * 30.0) : (5.0 + Random().nextDouble() * 20.0);
      final type = isAnomaly ? (Random().nextBool() ? 'PortScan' : 'Novel Zero-Day') : 'BENIGN';

      _latestAssessment = ThreatAssessment.mock(type: type, risk: risk);

      if (risk >= 60.0) {
        _threatsDetected++;
        _alertsHistory.insert(0, _latestAssessment);
        if (_alertsHistory.length > 20) _alertsHistory.removeLast();
      }

      notifyListeners();
    });
  }

  void _stopLiveInspection() {
    _pollingTimer?.cancel();
    _pollingTimer = null;
  }

  void injectTestThreat(String attackType) {
    _totalFlowsScanned++;
    double risk = 12.0;
    if (attackType == 'DDoS') risk = 96.4;
    if (attackType == 'PortScan') risk = 84.2;
    if (attackType == 'Botnet') risk = 89.1;
    if (attackType == 'Novel Zero-Day') risk = 79.5;

    _latestAssessment = ThreatAssessment.mock(type: attackType, risk: risk);

    if (risk >= 60.0) {
      _threatsDetected++;
      _alertsHistory.insert(0, _latestAssessment);
      if (_alertsHistory.length > 20) _alertsHistory.removeLast();
    }

    notifyListeners();
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    super.dispose();
  }
}
