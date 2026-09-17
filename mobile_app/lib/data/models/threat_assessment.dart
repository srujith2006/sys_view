class ModelMetric {
  final String name;
  final String role;
  final String status;
  final double score;
  final double latencyMs;

  const ModelMetric({
    required this.name,
    required this.role,
    required this.status,
    required this.score,
    required this.latencyMs,
  });

  factory ModelMetric.fromRaw(String rawName, Map<String, dynamic> json) {
    // Map technical model names into short, easy-to-understand terms
    String friendlyName = rawName;
    String friendlyRole = 'AI Safety Check';

    if (rawName.toLowerCase().contains('random') || rawName.toLowerCase().contains('classifier')) {
      friendlyName = 'Known Threat Matcher';
      friendlyRole = 'Checks known attack patterns';
    } else if (rawName.toLowerCase().contains('isolation') || rawName.toLowerCase().contains('forest')) {
      friendlyName = 'Behavior Checker';
      friendlyRole = 'Finds abnormal traffic spikes';
    } else if (rawName.toLowerCase().contains('autoencoder') || rawName.toLowerCase().contains('deep')) {
      friendlyName = 'Neural Pattern Scan';
      friendlyRole = 'Learns normal habits & spots anomalies';
    } else if (rawName.toLowerCase().contains('quantum') || rawName.toLowerCase().contains('qml')) {
      friendlyName = 'Quantum AI Guard';
      friendlyRole = 'Next-gen smart protection';
    }

    String rawStatus = json['status']?.toString() ?? 'NORMAL';
    String friendlyStatus = 'Safe';
    if (rawStatus.toUpperCase().contains('ANOMAL') || rawStatus.toUpperCase().contains('ATTACK')) {
      friendlyStatus = 'Unusual';
    } else if (rawStatus.toUpperCase() != 'NORMAL' && rawStatus.toUpperCase() != 'BENIGN') {
      friendlyStatus = rawStatus;
    }

    return ModelMetric(
      name: friendlyName,
      role: friendlyRole,
      status: friendlyStatus,
      score: (json['score'] as num?)?.toDouble() ?? 
             (json['anomaly_score'] as num?)?.toDouble() ?? 
             (json['confidence'] as num?)?.toDouble() ?? 0.0,
      latencyMs: (json['latency_ms'] as num?)?.toDouble() ?? 0.1,
    );
  }
}

class ThreatAssessment {
  final double riskScore;
  final String riskLevel;
  final String primaryStatus;
  final String attackType;
  final String summary;
  final List<String> reasons;
  final ModelMetric rf;
  final ModelMetric iforest;
  final ModelMetric autoencoder;
  final ModelMetric qml;
  final DateTime timestamp;

  const ThreatAssessment({
    required this.riskScore,
    required this.riskLevel,
    required this.primaryStatus,
    required this.attackType,
    required this.summary,
    required this.reasons,
    required this.rf,
    required this.iforest,
    required this.autoencoder,
    required this.qml,
    required this.timestamp,
  });

  factory ThreatAssessment.fromJson(Map<String, dynamic> json) {
    final fusion = json['fusion'] as Map<String, dynamic>? ?? {};
    final models = json['models'] as Map<String, dynamic>? ?? {};
    final explain = json['explainability'] as Map<String, dynamic>? ?? {};

    final rawScore = (fusion['risk_score'] as num?)?.toDouble() ?? 0.0;
    
    // Convert to simple, friendly status words
    String friendlyLevel = 'Safe';
    if (rawScore >= 80) {
      friendlyLevel = 'High Threat';
    } else if (rawScore >= 60) {
      friendlyLevel = 'Suspicious';
    } else if (rawScore >= 30) {
      friendlyLevel = 'Low Risk';
    }

    String rawStatus = fusion['primary_status']?.toString() ?? 'NORMAL';
    String friendlyStatus = 'All Safe';
    if (rawStatus.contains('NOVEL')) {
      friendlyStatus = 'Unusual Activity';
    } else if (rawStatus.contains('ATTACK')) {
      friendlyStatus = 'Threat Detected';
    }

    // Convert technical attack names to simple words
    String rawAttack = (models['random_forest']?['prediction'])?.toString() ?? 'BENIGN';
    String friendlyAttack = 'Normal Internet Traffic';
    if (rawAttack.toUpperCase() == 'DDOS') friendlyAttack = 'Traffic Flood (DDoS)';
    if (rawAttack.toUpperCase() == 'PORTSCAN') friendlyAttack = 'Port Scanning';
    if (rawAttack.toUpperCase() == 'BOTNET') friendlyAttack = 'Suspicious Botnet';
    if (rawAttack.toUpperCase() == 'BRUTEFORCE') friendlyAttack = 'Repeated Password Guesses';

    // Simplify reasons
    final reasonsList = <String>[];
    if (explain['top_deviations'] is List) {
      for (final item in explain['top_deviations']) {
        if (item is Map && item['narrative'] != null) {
          String line = item['narrative'].toString();
          // Remove intimidating technical jargon
          line = line.replaceAll('Forward Packet Count', 'Sent packet count')
                     .replaceAll('Network Bandwidth Throughput', 'Data transfer rate')
                     .replaceAll('SYN Connection Flags', 'Connection requests')
                     .replaceAll('benign baseline', 'normal level');
          reasonsList.add(line);
        }
      }
    }

    String friendlySummary = rawScore < 30
        ? 'Your network is safe. No unusual activity detected.'
        : 'Unusual internet traffic detected. Review details below.';

    return ThreatAssessment(
      riskScore: rawScore,
      riskLevel: friendlyLevel,
      primaryStatus: friendlyStatus,
      attackType: friendlyAttack,
      summary: friendlySummary,
      reasons: reasonsList.isEmpty 
          ? (rawScore < 30 ? ['Normal data speed', 'Normal connection count'] : ['Unusual traffic spike detected']) 
          : reasonsList,
      rf: ModelMetric.fromRaw('Random Forest', models['random_forest'] as Map<String, dynamic>? ?? {}),
      iforest: ModelMetric.fromRaw('Isolation Forest', models['isolation_forest'] as Map<String, dynamic>? ?? {}),
      autoencoder: ModelMetric.fromRaw('Deep Autoencoder', models['autoencoder'] as Map<String, dynamic>? ?? {}),
      qml: ModelMetric.fromRaw('Qiskit Quantum Kernel', models['quantum_kernel_svm'] as Map<String, dynamic>? ?? {}),
      timestamp: DateTime.now(),
    );
  }

  factory ThreatAssessment.mock({required String type, required double risk}) {
    String friendlyLevel = 'Safe';
    if (risk >= 80) {
      friendlyLevel = 'High Threat';
    } else if (risk >= 60) {
      friendlyLevel = 'Suspicious';
    } else if (risk >= 30) {
      friendlyLevel = 'Low Risk';
    }

    String friendlyStatus = 'All Safe';
    String friendlySummary = 'Your connection is safe. Everything is working normally.';
    List<String> friendlyReasons = [
      'Normal data transfer speed',
      'Normal connection rate',
    ];

    String friendlyAttack = 'Normal Internet Traffic';

    if (type == 'DDoS') {
      friendlyAttack = 'Traffic Flood (DDoS)';
      friendlyStatus = 'Threat Detected';
      friendlySummary = 'Sudden flood of internet traffic trying to overload your connection.';
      friendlyReasons = [
        'Huge surge in incoming data packets',
        'Abnormal connection requests',
        'Over 10x higher than normal traffic',
      ];
    } else if (type == 'PortScan') {
      friendlyAttack = 'Port Scanning';
      friendlyStatus = 'Threat Detected';
      friendlySummary = 'An outside device is probing your phone to find open ports.';
      friendlyReasons = [
        'Rapid attempts to connect to multiple ports',
        'Short unfinished connections',
      ];
    } else if (type == 'Novel Zero-Day') {
      friendlyAttack = 'Unusual New Behavior';
      friendlyStatus = 'Unusual Activity';
      friendlySummary = 'Traffic does not match known attacks, but acts very different from normal.';
      friendlyReasons = [
        'Unusual traffic pattern not seen before',
        'Higher than normal data bursts',
        'AI detected unexpected behavior',
      ];
    }

    return ThreatAssessment(
      riskScore: risk,
      riskLevel: friendlyLevel,
      primaryStatus: friendlyStatus,
      attackType: friendlyAttack,
      summary: friendlySummary,
      reasons: friendlyReasons,
      rf: ModelMetric(
        name: 'Known Threat Matcher',
        role: 'Checks known attacks',
        status: risk > 60 ? 'Matched' : 'Safe',
        score: risk / 100.0,
        latencyMs: 0.04,
      ),
      iforest: ModelMetric(
        name: 'Behavior Checker',
        role: 'Finds abnormal traffic',
        status: risk > 50 ? 'Unusual' : 'Safe',
        score: risk / 100.0,
        latencyMs: 0.03,
      ),
      autoencoder: ModelMetric(
        name: 'Neural Pattern Scan',
        role: 'Learns normal habits',
        status: risk > 60 ? 'Unusual' : 'Safe',
        score: (risk * 0.002),
        latencyMs: 1.2,
      ),
      qml: ModelMetric(
        name: 'Quantum AI Guard',
        role: 'Smart advanced check',
        status: risk > 60 ? 'Alert' : 'Safe',
        score: risk / 100.0,
        latencyMs: 3.4,
      ),
      timestamp: DateTime.now(),
    );
  }
}
