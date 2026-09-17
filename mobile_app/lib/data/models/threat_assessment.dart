class ModelMetric {
  final String name;
  final String status;
  final double score;
  final double latencyMs;

  const ModelMetric({
    required this.name,
    required this.status,
    required this.score,
    required this.latencyMs,
  });

  factory ModelMetric.fromJson(String name, Map<String, dynamic> json) {
    return ModelMetric(
      name: name,
      status: json['status']?.toString() ?? 'NORMAL',
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

    final reasonsList = <String>[];
    if (explain['top_deviations'] is List) {
      for (final item in explain['top_deviations']) {
        if (item is Map && item['narrative'] != null) {
          reasonsList.add(item['narrative'].toString());
        }
      }
    }

    return ThreatAssessment(
      riskScore: (fusion['risk_score'] as num?)?.toDouble() ?? 0.0,
      riskLevel: fusion['risk_level']?.toString() ?? 'SAFE',
      primaryStatus: fusion['primary_status']?.toString() ?? 'NORMAL',
      attackType: (models['random_forest']?['prediction'])?.toString() ?? 'BENIGN',
      summary: explain['narrative']?.toString() ?? 'Traffic within safe operational bounds.',
      reasons: reasonsList,
      rf: ModelMetric.fromJson('Random Forest', models['random_forest'] as Map<String, dynamic>? ?? {}),
      iforest: ModelMetric.fromJson('Isolation Forest', models['isolation_forest'] as Map<String, dynamic>? ?? {}),
      autoencoder: ModelMetric.fromJson('Deep Autoencoder', models['autoencoder'] as Map<String, dynamic>? ?? {}),
      qml: ModelMetric.fromJson('Qiskit Quantum Kernel', models['quantum_kernel_svm'] as Map<String, dynamic>? ?? {}),
      timestamp: DateTime.now(),
    );
  }

  factory ThreatAssessment.mock({required String type, required double risk}) {
    return ThreatAssessment(
      riskScore: risk,
      riskLevel: risk < 30 ? 'SAFE' : (risk < 70 ? 'MEDIUM' : 'CRITICAL'),
      primaryStatus: risk < 30 ? 'NORMAL' : (risk < 70 ? 'POTENTIAL NOVEL ANOMALY' : 'KNOWN ATTACK'),
      attackType: type,
      summary: risk < 30 
          ? 'Network flow parameters match baseline benign distributions.'
          : 'High volume abnormal packet burst and unusual TCP SYN flag distribution.',
      reasons: risk < 30 
          ? ['Packet rate: 2.1 pkts/s (Normal)', 'Flow duration: 45ms (Normal)']
          : ['Packet rate: 3,420 pkts/s (Elevated)', 'SYN Flag ratio: 98% (Abnormal)', 'Flow byte deviation: +4.8σ'],
      rf: ModelMetric(name: 'Random Forest', status: type, score: risk / 100.0, latencyMs: 0.04),
      iforest: ModelMetric(name: 'Isolation Forest', status: risk > 50 ? 'ANOMALOUS' : 'NORMAL', score: risk / 100.0, latencyMs: 0.03),
      autoencoder: ModelMetric(name: 'Deep Autoencoder', status: risk > 60 ? 'ANOMALOUS' : 'NORMAL', score: (risk * 0.002), latencyMs: 1.2),
      qml: ModelMetric(name: 'Qiskit Quantum Kernel', status: type, score: risk / 100.0, latencyMs: 3.4),
      timestamp: DateTime.now(),
    );
  }
}
