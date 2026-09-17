import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../../../core/theme.dart';
import '../../../../data/models/threat_assessment.dart';
import '../view_models/dashboard_view_model.dart';
import '../../settings/settings_screen.dart';

class DashboardScreen extends StatelessWidget {
  final DashboardViewModel viewModel;

  const DashboardScreen({super.key, required this.viewModel});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: viewModel,
      builder: (context, _) {
        final current = viewModel.latestAssessment;
        final riskColor = SocTheme.getRiskColor(current.riskScore);

        return Scaffold(
          appBar: AppBar(
            title: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(
                    color: SocTheme.cyanAccent.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.shield_outlined, color: SocTheme.cyanAccent, size: 22),
                ),
                const SizedBox(width: 10),
                const Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'ThreatGuard',
                      style: TextStyle(fontSize: 17, fontWeight: FontWeight.bold),
                    ),
                    Text(
                      'Smart Network Shield',
                      style: TextStyle(fontSize: 11, color: Colors.white54),
                    ),
                  ],
                ),
              ],
            ),
            actions: [
              IconButton(
                icon: const Icon(Icons.settings_outlined, color: Colors.white70),
                onPressed: () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => SettingsScreen(viewModel: viewModel),
                    ),
                  );
                },
              ),
            ],
          ),
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // 1. Consent & Protection Switch
                _buildProtectionCard(context),

                const SizedBox(height: 16),

                // 2. Clear Threat Level Gauge
                _buildThreatGaugeCard(current, riskColor),

                const SizedBox(height: 16),

                // 3. Quick Tryout Chips
                _buildDemoBar(),

                const SizedBox(height: 16),

                // 4. 4-Layer Protection Overview
                _buildLayersGrid(current),

                const SizedBox(height: 16),

                // 5. Plain English Findings
                _buildFindingsCard(current),

                const SizedBox(height: 16),

                // 6. Recent Alerts
                _buildAlertsHistoryCard(),

                const SizedBox(height: 30),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildProtectionCard(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: SocTheme.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: viewModel.isMonitoring ? SocTheme.cyanAccent : SocTheme.border,
          width: viewModel.isMonitoring ? 1.5 : 1,
        ),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Icon(
                viewModel.hasConsent ? Icons.verified_user : Icons.privacy_tip_outlined,
                color: viewModel.hasConsent ? SocTheme.normalGreen : SocTheme.warningAmber,
                size: 22,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Network Protection',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
                    ),
                    Text(
                      viewModel.hasConsent
                          ? 'Only checks connection safety. Never reads private chats or photos.'
                          : 'Turn on to let the app watch for dangerous connections.',
                      style: const TextStyle(fontSize: 11, color: Colors.white54),
                    ),
                  ],
                ),
              ),
              Switch(
                value: viewModel.hasConsent,
                activeColor: SocTheme.normalGreen,
                onChanged: (val) => viewModel.grantConsent(val),
              ),
            ],
          ),
          if (viewModel.hasConsent) ...[
            const Divider(color: SocTheme.border, height: 20),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    Container(
                      width: 8,
                      height: 8,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: viewModel.isMonitoring ? SocTheme.normalGreen : Colors.grey,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      viewModel.isMonitoring ? 'Active (Uses almost no battery)' : 'Paused',
                      style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                    ),
                  ],
                ),
                Switch(
                  value: viewModel.isMonitoring,
                  activeColor: SocTheme.cyanAccent,
                  onChanged: (val) => viewModel.toggleMonitoring(val),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildThreatGaugeCard(ThreatAssessment current, Color riskColor) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 16),
      decoration: BoxDecoration(
        color: SocTheme.surface,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: SocTheme.border),
      ),
      child: Column(
        children: [
          // Circular Gauge
          SizedBox(
            width: 180,
            height: 180,
            child: CustomPaint(
              painter: _RiskGaugePainter(
                score: current.riskScore,
                riskColor: riskColor,
              ),
              child: Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      current.riskScore.toStringAsFixed(0),
                      style: TextStyle(
                        fontSize: 42,
                        fontWeight: FontWeight.w900,
                        color: riskColor,
                        letterSpacing: -1,
                      ),
                    ),
                    const Text(
                      'THREAT LEVEL',
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        color: Colors.white54,
                        letterSpacing: 1.5,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
          const SizedBox(height: 16),
          // Status Pills
          Wrap(
            spacing: 8,
            alignment: WrapAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                decoration: BoxDecoration(
                  color: riskColor.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: riskColor),
                ),
                child: Text(
                  current.riskLevel,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: riskColor,
                  ),
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                decoration: BoxDecoration(
                  color: SocTheme.surfaceElevated,
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: SocTheme.border),
                ),
                child: Text(
                  current.primaryStatus,
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: Colors.white,
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildDemoBar() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'TRY SAMPLE ALERTS',
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.bold,
            color: Colors.white54,
            letterSpacing: 1,
          ),
        ),
        const SizedBox(height: 8),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: Row(
            children: [
              _buildSimChip('Safe Traffic', 'BENIGN', SocTheme.normalGreen),
              const SizedBox(width: 8),
              _buildSimChip('Traffic Flood', 'DDoS', SocTheme.criticalRed),
              const SizedBox(width: 8),
              _buildSimChip('Port Probe', 'PortScan', SocTheme.warningAmber),
              const SizedBox(width: 8),
              _buildSimChip('New Threat', 'Novel Zero-Day', SocTheme.quantumPurple),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildSimChip(String label, String type, Color color) {
    return ActionChip(
      avatar: Icon(Icons.bolt, color: color, size: 16),
      label: Text(label, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600)),
      backgroundColor: color.withOpacity(0.1),
      side: BorderSide(color: color.withOpacity(0.4)),
      onPressed: () => viewModel.injectTestThreat(type),
    );
  }

  Widget _buildLayersGrid(ThreatAssessment current) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          '4-LAYER PROTECTION',
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.bold,
            color: Colors.white54,
            letterSpacing: 1,
          ),
        ),
        const SizedBox(height: 8),
        GridView.count(
          crossAxisCount: 2,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          mainAxisSpacing: 10,
          crossAxisSpacing: 10,
          childAspectRatio: 1.55,
          children: [
            _buildModelCard(current.rf.name, current.rf.role, current.rf.status, SocTheme.cyanAccent),
            _buildModelCard(current.iforest.name, current.iforest.role, current.iforest.status, SocTheme.normalGreen),
            _buildModelCard(current.autoencoder.name, current.autoencoder.role, current.autoencoder.status, SocTheme.warningAmber),
            _buildModelCard(current.qml.name, current.qml.role, current.qml.status, SocTheme.quantumPurple),
          ],
        ),
      ],
    );
  }

  Widget _buildModelCard(String name, String role, String status, Color accent) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: SocTheme.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: SocTheme.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Text(
                  name,
                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              Container(
                width: 7,
                height: 7,
                decoration: BoxDecoration(color: accent, shape: BoxShape.circle),
              ),
            ],
          ),
          Text(
            role,
            style: const TextStyle(fontSize: 10, color: Colors.white38),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            decoration: BoxDecoration(
              color: accent.withOpacity(0.12),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              status,
              style: TextStyle(color: accent, fontSize: 11, fontWeight: FontWeight.bold),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFindingsCard(ThreatAssessment current) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: SocTheme.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: SocTheme.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.info_outline, color: SocTheme.cyanAccent, size: 20),
              SizedBox(width: 8),
              Text(
                'WHAT WAS FOUND?',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 0.5,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            current.summary,
            style: const TextStyle(fontSize: 13, color: Colors.white70, height: 1.4),
          ),
          const SizedBox(height: 8),
          ...current.reasons.map((r) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 3),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('• ', style: TextStyle(color: SocTheme.cyanAccent, fontSize: 14)),
                    Expanded(
                      child: Text(r, style: const TextStyle(fontSize: 12, color: Colors.white60)),
                    ),
                  ],
                ),
              )),
        ],
      ),
    );
  }

  Widget _buildAlertsHistoryCard() {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: SocTheme.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: SocTheme.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'RECENT ALERTS',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 0.5,
                ),
              ),
              Text(
                'Total: ${viewModel.threatsDetected}',
                style: const TextStyle(fontSize: 11, color: Colors.white54),
              ),
            ],
          ),
          const SizedBox(height: 10),
          if (viewModel.alertsHistory.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 12),
              child: Center(
                child: Text(
                  'No threats detected yet. Device is safe.',
                  style: TextStyle(color: Colors.white38, fontSize: 12),
                ),
              ),
            )
          else
            ...viewModel.alertsHistory.take(4).map((a) {
              final color = SocTheme.getRiskColor(a.riskScore);
              return Container(
                margin: const EdgeInsets.only(bottom: 8),
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: SocTheme.surfaceElevated,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          a.attackType,
                          style: TextStyle(
                            color: color,
                            fontWeight: FontWeight.bold,
                            fontSize: 13,
                          ),
                        ),
                        Text(
                          a.primaryStatus,
                          style: const TextStyle(fontSize: 10, color: Colors.white54),
                        ),
                      ],
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: color.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        'Threat: ${a.riskScore.toStringAsFixed(0)}',
                        style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 11),
                      ),
                    ),
                  ],
                ),
              );
            }),
        ],
      ),
    );
  }
}

class _RiskGaugePainter extends CustomPainter {
  final double score;
  final Color riskColor;

  _RiskGaugePainter({required this.score, required this.riskColor});

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2 - 12;

    const startAngle = math.pi * 0.75;
    const sweepAngle = math.pi * 1.5;

    // Track Paint
    final trackPaint = Paint()
      ..color = SocTheme.border
      ..style = PaintingStyle.stroke
      ..strokeWidth = 10
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      sweepAngle,
      false,
      trackPaint,
    );

    // Active Paint
    final activeSweep = (score / 100.0) * sweepAngle;
    final activePaint = Paint()
      ..color = riskColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = 10
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      activeSweep,
      false,
      activePaint,
    );
  }

  @override
  bool shouldRepaint(covariant _RiskGaugePainter oldDelegate) {
    return oldDelegate.score != score || oldDelegate.riskColor != riskColor;
  }
}
