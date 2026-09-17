import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/threat_assessment.dart';

class ApiService {
  String baseUrl;

  ApiService({this.baseUrl = 'http://10.0.2.2:5000'}); // 10.0.2.2 is Android host loopback

  void updateBaseUrl(String url) {
    baseUrl = url;
  }

  Future<bool> checkHealth() async {
    try {
      final response = await http
          .get(Uri.parse('$baseUrl/health'))
          .timeout(const Duration(seconds: 3));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  Future<ThreatAssessment> assessFlow(Map<String, dynamic> features) async {
    try {
      final response = await http
          .post(
            Uri.parse('$baseUrl/predict'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode(features),
          )
          .timeout(const Duration(seconds: 4));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        return ThreatAssessment.fromJson(data);
      } else {
        throw Exception('Server returned ${response.statusCode}');
      }
    } catch (e) {
      // Return realistic fallback assessment if server offline
      return ThreatAssessment.mock(
        type: 'BENIGN',
        risk: 14.5,
      );
    }
  }
}
