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
        title: const Text('App Settings'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _buildSectionHeader('CONNECT TO COMPUTER'),
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
                  'Computer Wi-Fi Address',
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
                        label: const Text('Save & Test Connection'),
                        onPressed: () {
                          widget.viewModel.updateServerUrl(_urlController.text.trim());
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Saved computer address.')),
                          );
                        },
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  widget.viewModel.isConnectedToServer 
                      ? "🟢 Connected to your computer" 
                      : "⚪ Standalone Mode (Works without computer)",
                  style: const TextStyle(fontSize: 11, color: Colors.white60),
                ),
              ],
            ),
          ),

          const SizedBox(height: 20),
          _buildSectionHeader('NOTIFICATION SETTINGS'),
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
                    const Text('Alert me when threat level is at least:', style: TextStyle(fontSize: 12)),
                    Text(
                      '${_alertThreshold.toInt()}',
                      style: const TextStyle(color: SocTheme.warningAmber, fontWeight: FontWeight.bold, fontSize: 13),
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
                  title: const Text('Sound & Vibration Alert', style: TextStyle(fontSize: 13)),
                  subtitle: const Text('Play sound when high threat is found', style: TextStyle(fontSize: 11, color: Colors.white54)),
                  value: _soundEnabled,
                  activeColor: SocTheme.cyanAccent,
                  onChanged: (val) => setState(() => _soundEnabled = val),
                ),
              ],
            ),
          ),

          const SizedBox(height: 20),
          _buildSectionHeader('YOUR PRIVACY'),
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
                    Text('100% Private & Safe', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                  ],
                ),
                SizedBox(height: 8),
                Text(
                  '• We never read your personal messages, photos, or passwords.\n'
                  '• We only look at network traffic speed and connection safety.\n'
                  '• Optimized to use almost no phone battery.',
                  style: TextStyle(fontSize: 12, color: Colors.white70, height: 1.6),
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
