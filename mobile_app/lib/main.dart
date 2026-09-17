import 'package:flutter/material.dart';
import 'ui/core/theme.dart';
import 'ui/features/dashboard/views/dashboard_screen.dart';
import 'ui/features/dashboard/view_models/dashboard_view_model.dart';
import 'data/services/api_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  
  final apiService = ApiService(baseUrl: 'http://10.0.2.2:5000');
  final dashboardViewModel = DashboardViewModel(apiService: apiService);

  runApp(QenidsApp(viewModel: dashboardViewModel));
}

class QenidsApp extends StatelessWidget {
  final DashboardViewModel viewModel;

  const QenidsApp({super.key, required this.viewModel});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'QE-NIDS ThreatGuard',
      debugShowCheckedModeBanner: false,
      theme: SocTheme.darkTheme,
      home: DashboardScreen(viewModel: viewModel),
    );
  }
}
