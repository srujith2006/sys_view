import 'package:flutter/material.dart';
import '../../core/theme.dart';
import '../dashboard/view_models/dashboard_view_model.dart';

class SettingsScreen extends StatefulWidget {
  final DashboardViewModel viewModel;

  const SettingsScreen({super.key, required this.viewModel});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late TextEditingController _urlController;
  double _alertThreshold = 70.0;
  bool _soundEnabled = true;

  @override
  void initState() {
    super.initState();
    _urlController = TextEditingController(text: widget.viewModel.serverUrl);
  }

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Agent Settings'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _buildSectionHeader('BACKEND ENGINE LINK'),
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: SocTheme.surface,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: SocTheme.border),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'QE-NIDS REST Server URL',
                  style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _urlController,
                  decoration: InputDecoration(
                    hintText: 'http://192.168.1.xxx:5000',
                    filled: true,
                    fillColor: SocTheme.surfaceElevated,
                    contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10),
                      borderSide: BorderSide.none,
                    ),
                  ),
                ),
                const SizedBox(height: 10),
                Row(
                  children: [
                    Expanded(
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: SocTheme.cyanAccent.withOpacity(0.15),
                          foregroundColor: SocTheme.cyanAccent,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                        ),
                        icon: const Icon(Icons.sync, size: 18),
                        label: const Text('Save & Test Link'),
                        onPressed: () {
                          widget.viewModel.updateServerUrl(_urlController.text.trim());
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Updated server configuration.')),
                          );
                        },
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  'Current link: ${widget.viewModel.isConnectedToServer ? "🟢 Connected" : "⚪ Offline / Demo Mode"}',
                  style: const TextStyle(fontSize: 11, color: Colors.white54),
                ),
              ],
            ),
          ),

          const SizedBox(height: 20),
          _buildSectionHeader('NOTIFICATION THRESHOLDS'),
          Container(
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
                    const Text('Alert Sensitivity', style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                    Text(
                      'Score ≥ ${_alertThreshold.toInt()}',
                      style: const TextStyle(color: SocTheme.warningAmber, fontWeight: FontWeight.bold),
                    ),
                  ],
                ),
                Slider(
                  value: _alertThreshold,
                  min: 40.0,
                  max: 90.0,
                  divisions: 5,
                  activeColor: SocTheme.cyanAccent,
                  inactiveColor: SocTheme.border,
                  onChanged: (val) {
                    setState(() => _alertThreshold = val);
                  },
                ),
                const Divider(color: SocTheme.border, height: 20),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Audible Alarm & Vibration', style: TextStyle(fontSize: 13)),
                  subtitle: const Text('Trigger sound for High and Critical threats', style: TextStyle(fontSize: 11, color: Colors.white54)),
                  value: _soundEnabled,
                  activeColor: SocTheme.cyanAccent,
                  onChanged: (val) => setState(() => _soundEnabled = val),
                ),
              ],
            ),
          ),

          const SizedBox(height: 20),
          _buildSectionHeader('PRIVACY & SECURITY SCOPE'),
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: SocTheme.surface,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: SocTheme.border),
            ),
            child: const Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.shield, color: SocTheme.normalGreen, size: 20),
                    SizedBox(width: 8),
                    Text('Strict Privacy Guarantees', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                  ],
                ),
                SizedBox(height: 8),
                Text(
                  '• Only 51 statistical flow metrics (packet counts, byte rates, duration) are processed.\n'
                  '• User payloads, passwords, messages, and browsed web contents are NEVER captured or stored.\n'
                  '• Battery-preserving tiered evaluation keeps background CPU utilization under 0.1%.',
                  style: TextStyle(fontSize: 11, color: Colors.white70, height: 1.5),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Padding(
      padding: const EdgeInsets.only(left: 4, bottom: 8),
      child: Text(
        title,
        style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.white54, letterSpacing: 1),
      ),
    );
  }
}
