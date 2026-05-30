using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace TaaProxy
{
    internal class InputDialog : Window
    {
        private readonly TextBox _input;
        public string Result => _input.Text;

        private static readonly Color C_BG = (Color)ColorConverter.ConvertFromString("#07090F");
        private static readonly Color C_HEAD = (Color)ColorConverter.ConvertFromString("#0B1020");
        private static readonly Color C_BORD = (Color)ColorConverter.ConvertFromString("#1A2640");
        private static readonly Color C_TXT = (Color)ColorConverter.ConvertFromString("#F0F4FF");
        private static readonly Color C_MUTED = (Color)ColorConverter.ConvertFromString("#4B5A7A");
        private static readonly Color C_ACC = (Color)ColorConverter.ConvertFromString("#6366F1");

        private static SolidColorBrush Br(Color c) => new(c);

        public InputDialog(string title, string prompt, string defaultValue = "")
        {
            Title = title;
            Width = 420; Height = 185;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = Br(C_BG);
            WindowStyle = WindowStyle.None;
            FontFamily = new FontFamily("Segoe UI");

            WindowChrome.SetWindowChrome(this, new WindowChrome
            {
                CaptionHeight = 36,
                ResizeBorderThickness = new Thickness(0),
                UseAeroCaptionButtons = false,
                GlassFrameThickness = new Thickness(0)
            });

            var titleBar = new Border
            {
                Background = Br(C_HEAD),
                Height = 36,
                BorderBrush = Br(C_BORD),
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            var tbGrid = new Grid();
            tbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            tbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleText = new TextBlock
            {
                Text = title,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Foreground = Br(C_MUTED),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(14, 0, 0, 0)
            };
            Grid.SetColumn(titleText, 0);
            tbGrid.Children.Add(titleText);

            var closeBtn = new Button
            {
                Content = "⛌",
                Width = 40,
                Height = 36,
                Background = Brushes.Transparent,
                Foreground = Br(C_MUTED),
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                FontSize = 11
            };
            closeBtn.MouseEnter += (_, _) => { closeBtn.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444")); closeBtn.Foreground = Brushes.White; };
            closeBtn.MouseLeave += (_, _) => { closeBtn.Background = Brushes.Transparent; closeBtn.Foreground = Br(C_MUTED); };
            closeBtn.Click += (_, _) => { DialogResult = false; };
            WindowChrome.SetIsHitTestVisibleInChrome(closeBtn, true);
            Grid.SetColumn(closeBtn, 1);
            tbGrid.Children.Add(closeBtn);
            titleBar.Child = tbGrid;

            var body = new StackPanel { Margin = new Thickness(20, 16, 20, 20) };
            body.Children.Add(new TextBlock
            {
                Text = prompt,
                FontSize = 13,
                Margin = new Thickness(0, 0, 0, 8),
                Foreground = Br(C_MUTED),
                TextWrapping = TextWrapping.Wrap
            });

            _input = new TextBox
            {
                Text = defaultValue,
                FontSize = 13,
                Height = 38,
                Background = Br((Color)ColorConverter.ConvertFromString("#0D1526")),
                Foreground = Br(C_TXT),
                BorderBrush = Br(C_ACC),
                BorderThickness = new Thickness(1),
                CaretBrush = Br(C_TXT),
                Padding = new Thickness(10, 0, 10, 0),
                Margin = new Thickness(0, 0, 0, 14),
                VerticalContentAlignment = VerticalAlignment.Center
            };
            _input.KeyDown += (_, e) => { if (e.Key == Key.Enter) DialogResult = true; if (e.Key == Key.Escape) DialogResult = false; };

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var okBtn = MakeDialogBtn("OK", C_ACC, true);
            var cancelBtn = MakeDialogBtn("Отмена", (Color)ColorConverter.ConvertFromString("#111E38"), false);
            okBtn.Click += (_, _) => { DialogResult = true; };
            cancelBtn.Click += (_, _) => { DialogResult = false; };
            btnRow.Children.Add(okBtn);
            btnRow.Children.Add(cancelBtn);

            body.Children.Add(_input);
            body.Children.Add(btnRow);

            var outer = new DockPanel();
            DockPanel.SetDock(titleBar, Dock.Top);
            outer.Children.Add(titleBar);
            outer.Children.Add(body);
            Content = outer;

            Loaded += (_, _) => { _input.Focus(); _input.SelectAll(); };
        }

        private static Button MakeDialogBtn(string text, Color bg, bool isOk)
        {
            var btn = new Button
            {
                Content = text,
                Width = 80,
                Height = 32,
                Margin = isOk ? new Thickness(0, 0, 8, 0) : new Thickness(0),
                Background = new SolidColorBrush(bg),
                Foreground = Brushes.White,
                BorderThickness = new Thickness(isOk ? 0 : 1),
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3F3F46")),
                Cursor = Cursors.Hand,
                FontSize = 13
            };
            const string x = @"<ControlTemplate TargetType='Button'
                xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
                xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'>
              <Border x:Name='bd' Background='{TemplateBinding Background}'
                      BorderBrush='{TemplateBinding BorderBrush}'
                      BorderThickness='{TemplateBinding BorderThickness}'
                      CornerRadius='6'>
                <ContentPresenter HorizontalAlignment='Center' VerticalAlignment='Center'/>
              </Border>
            </ControlTemplate>";
            btn.Template = (ControlTemplate)XamlReader.Parse(x);
            return btn;
        }
    }
}