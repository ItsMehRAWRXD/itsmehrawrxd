package com.android.comprehensiveroot;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.graphics.Color;
import android.os.Handler;
import android.os.Looper;

public class MainActivity extends Activity {
    private ComprehensiveRootingApp rootApp;
    private TextView deviceInfoText;
    private TextView statusText;
    private TextView logText;
    private Button rootButton;
    private Button clearLogButton;
    private ScrollView logScrollView;
    private LinearLayout mainLayout;
    private Handler mainHandler;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        mainHandler = new Handler(Looper.getMainLooper());
        rootApp = new ComprehensiveRootingApp(this);
        
        initializeViews();
        setupClickListeners();
        displayDeviceInfo();
    }
    
    private void initializeViews() {
        deviceInfoText = findViewById(R.id.device_info_text);
        statusText = findViewById(R.id.status_text);
        logText = findViewById(R.id.log_text);
        rootButton = findViewById(R.id.root_button);
        clearLogButton = findViewById(R.id.clear_log_button);
        logScrollView = findViewById(R.id.log_scroll_view);
        mainLayout = findViewById(R.id.main_layout);
    }
    
    private void setupClickListeners() {
        rootButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startRootingProcess();
            }
        });
        
        clearLogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                clearLog();
            }
        });
    }
    
    private void displayDeviceInfo() {
        ComprehensiveRootingApp.DeviceInfo deviceInfo = rootApp.getDeviceInfo();
        
        StringBuilder info = new StringBuilder();
        info.append("Device Information:\n");
        info.append("Manufacturer: ").append(deviceInfo.manufacturer).append("\n");
        info.append("Model: ").append(deviceInfo.model).append("\n");
        info.append("Android Version: ").append(deviceInfo.androidVersion).append("\n");
        info.append("SDK Version: ").append(deviceInfo.sdkVersion).append("\n");
        info.append("Hardware: ").append(deviceInfo.hardware).append("\n");
        info.append("Board: ").append(deviceInfo.board).append("\n");
        info.append("Kernel: ").append(deviceInfo.kernelVersion).append("\n");
        info.append("Architecture: ").append(deviceInfo.kernelArchitecture).append("\n");
        info.append("Is Samsung: ").append(deviceInfo.isSamsung ? "Yes" : "No").append("\n");
        info.append("Is Galaxy Tab: ").append(deviceInfo.isGalaxyTab ? "Yes" : "No").append("\n");
        info.append("Knox Status: ").append(deviceInfo.knoxStatus).append("\n");
        info.append("Secure Boot: ").append(deviceInfo.secureBoot).append("\n");
        info.append("Verified Boot: ").append(deviceInfo.verifiedBoot).append("\n");
        info.append("OEM Unlock: ").append(deviceInfo.oemUnlockSupported ? "Supported" : "Not Supported").append("\n");
        info.append("Currently Rooted: ").append(deviceInfo.isRooted ? "Yes" : "No").append("\n");
        
        deviceInfoText.setText(info.toString());
        
        // Display available methods
        StringBuilder methods = new StringBuilder();
        methods.append("\nAvailable Rooting Methods:\n");
        for (ComprehensiveRootingApp.RootingMethod method : rootApp.getAvailableMethods()) {
            methods.append("• ").append(method.name).append(" (Success Rate: ").append((int)(method.successRate * 100)).append("%)\n");
        }
        
        deviceInfoText.append(methods.toString());
    }
    
    private void startRootingProcess() {
        rootButton.setEnabled(false);
        rootButton.setText("ROOTING IN PROGRESS...");
        statusText.setText("Starting rooting process...");
        statusText.setTextColor(Color.BLUE);
        
        appendLog("=== ROOTING PROCESS STARTED ===");
        appendLog("Device: " + rootApp.getDeviceInfo().model);
        appendLog("Android: " + rootApp.getDeviceInfo().androidVersion);
        appendLog("Available methods: " + rootApp.getAvailableMethods().size());
        
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    rootApp.attemptRooting();
                    
                    mainHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            rootingProcessCompleted();
                        }
                    });
                    
                } catch (Exception e) {
                    mainHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            rootingProcessFailed(e);
                        }
                    });
                }
            }
        }).start();
    }
    
    private void rootingProcessCompleted() {
        rootButton.setEnabled(true);
        rootButton.setText("ATTEMPT ROOT AGAIN");
        statusText.setText("Rooting process completed. Check logs for results.");
        statusText.setTextColor(Color.GREEN);
        
        appendLog("=== ROOTING PROCESS COMPLETED ===");
        appendLog("Check if root access is available");
        
        Toast.makeText(this, "Rooting process completed!", Toast.LENGTH_LONG).show();
    }
    
    private void rootingProcessFailed(Exception e) {
        rootButton.setEnabled(true);
        rootButton.setText("ATTEMPT ROOT AGAIN");
        statusText.setText("Rooting process failed: " + e.getMessage());
        statusText.setTextColor(Color.RED);
        
        appendLog("=== ROOTING PROCESS FAILED ===");
        appendLog("Error: " + e.getMessage());
        
        Toast.makeText(this, "Rooting process failed!", Toast.LENGTH_LONG).show();
    }
    
    private void appendLog(String message) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                String timestamp = java.text.DateFormat.getTimeInstance().format(new java.util.Date());
                logText.append("[" + timestamp + "] " + message + "\n");
                
                // Auto-scroll to bottom
                logScrollView.post(new Runnable() {
                    @Override
                    public void run() {
                        logScrollView.fullScroll(View.FOCUS_DOWN);
                    }
                });
            }
        });
    }
    
    private void clearLog() {
        logText.setText("");
        appendLog("Log cleared");
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (rootApp != null) {
            rootApp.cleanup();
        }
    }
}