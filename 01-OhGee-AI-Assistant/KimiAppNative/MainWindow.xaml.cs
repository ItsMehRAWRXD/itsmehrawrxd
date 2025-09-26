using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Web.WebView2.Core;
using System.Threading.Tasks;

namespace KimiAppNative
{
    public partial class MainWindow : Window
    {
        private string _currentAssistant = "Kimi";
        private SystemTrayManager _trayManager;
        private readonly string[] _assistantUrls = {
            "https://kimi.moonshot.cn/",           // Kimi AI
            "https://www.cursor.com/",             // Cursor
            "https://chat.openai.com/"             // ChatGPT
        };

        public MainWindow()
        {
            InitializeComponent();
            InitializeWebView();
            SetupEventHandlers();
            InitializeSystemTray();
            ShowAssistant("Kimi");
        }

        private async void InitializeWebView()
        {
            try
            {
                await WebView.EnsureCoreWebView2Async(null);
                WebView.CoreWebView2.Settings.IsStatusBarEnabled = false;
                WebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = true;
                WebView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to initialize WebView: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SetupEventHandlers()
        {
            // Enable window dragging
            this.MouseDown += (sender, e) =>
            {
                if (e.ChangedButton == MouseButton.Left)
                    this.DragMove();
            };

            // Handle window state changes
            this.StateChanged += (sender, e) =>
            {
                if (this.WindowState == WindowState.Minimized)
                {
                    this.Hide();
                }
            };
        }

        private void InitializeSystemTray()
        {
            _trayManager = new SystemTrayManager(this);
        }

        public void ShowAssistant(string assistantName)
        {
            _currentAssistant = assistantName;
            
            // Update tab appearance
            ResetTabStyles();
            switch (assistantName)
            {
                case "Kimi":
                    KimiTab.Background = new SolidColorBrush(Color.FromRgb(0, 120, 212));
                    NavigateToUrl(_assistantUrls[0]);
                    break;
                case "Cursor":
                    CursorTab.Background = new SolidColorBrush(Color.FromRgb(0, 120, 212));
                    NavigateToUrl(_assistantUrls[1]);
                    break;
                case "ChatGPT":
                    ChatGPTTab.Background = new SolidColorBrush(Color.FromRgb(0, 120, 212));
                    NavigateToUrl(_assistantUrls[2]);
                    break;
            }

            // Show and activate window
            if (this.Visibility != Visibility.Visible)
            {
                this.Show();
                this.Activate();
                this.Topmost = true;
                this.Topmost = false;
            }
        }

        private void ResetTabStyles()
        {
            KimiTab.Background = new SolidColorBrush(Color.FromRgb(108, 117, 125));
            CursorTab.Background = new SolidColorBrush(Color.FromRgb(108, 117, 125));
            ChatGPTTab.Background = new SolidColorBrush(Color.FromRgb(108, 117, 125));
        }

        private void NavigateToUrl(string url)
        {
            try
            {
                if (WebView.CoreWebView2 != null)
                {
                    WebView.CoreWebView2.Navigate(url);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to navigate to {url}: {ex.Message}", "Navigation Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void KimiTab_Click(object sender, RoutedEventArgs e)
        {
            ShowAssistant("Kimi");
        }

        private void CursorTab_Click(object sender, RoutedEventArgs e)
        {
            ShowAssistant("Cursor");
        }

        private void ChatGPTTab_Click(object sender, RoutedEventArgs e)
        {
            ShowAssistant("ChatGPT");
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Hide();
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            
            // Make window stay on top when activated
            this.Activated += (sender, args) => this.Topmost = true;
            this.Deactivated += (sender, args) => this.Topmost = false;
        }
    }
}
