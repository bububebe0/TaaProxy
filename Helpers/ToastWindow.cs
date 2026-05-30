using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace TaaProxy
{
    internal enum ToastType { Info, Success, Error }

    internal class ToastWindow : Window
    {
        private static readonly Color C_BG = (Color)ColorConverter.ConvertFromString("#08101E");
        private static readonly Color C_BORDER = (Color)ColorConverter.ConvertFromString("#1A2640");
        private static readonly Color C_TXT = (Color)ColorConverter.ConvertFromString("#F0F4FF");
        private static readonly Color C_MUTED = (Color)ColorConverter.ConvertFromString("#4B5A7A");
        private static readonly Color C_SUCCESS = (Color)ColorConverter.ConvertFromString("#10B981");
        private static readonly Color C_INFO = (Color)ColorConverter.ConvertFromString("#6366F1");
        private static readonly Color C_ERROR = (Color)ColorConverter.ConvertFromString("#EF4444");

        private static SolidColorBrush Br(Color c) => new(c);

        public ToastWindow(string title, string message, ToastType type)
        {
            Width = 300;
            Height = 90;
            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;
            Background = Brushes.Transparent;
            ShowInTaskbar = false;
            Topmost = true;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.Manual;

            var screen = SystemParameters.WorkArea;
            Left = screen.Right - Width - 20;
            Top = screen.Bottom - Height - 20;

            var border = new Border
            {
                Background = Br(C_BG),
                BorderBrush = Br(C_BORDER),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Opacity = 0,
                Effect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    Color = Colors.Black, BlurRadius = 28, ShadowDepth = 4, Opacity = 0.55
                }
            };

            var grid = new Grid { Margin = new Thickness(16, 12, 16, 12) };
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var header = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
            var color = type switch { ToastType.Success => C_SUCCESS, ToastType.Error => C_ERROR, _ => C_INFO };
            var dot = new Ellipse { Width = 10, Height = 10, Fill = Br(color), Margin = new Thickness(0, 0, 8, 0) };
            var titleBlock = new TextBlock { Text = title, FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Br(C_TXT) };
            header.Children.Add(dot);
            header.Children.Add(titleBlock);
            Grid.SetRow(header, 0);
            grid.Children.Add(header);

            var msgBlock = new TextBlock { Text = message, FontSize = 12, Foreground = Br(C_MUTED), TextWrapping = TextWrapping.Wrap };
            Grid.SetRow(msgBlock, 1);
            grid.Children.Add(msgBlock);

            border.Child = grid;
            Content = border;

            Loaded += async (_, _) =>
            {
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200));
                border.BeginAnimation(OpacityProperty, fadeIn);

                await Task.Delay(4000);

                var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(200));
                fadeOut.Completed += (_, _) => Close();
                border.BeginAnimation(OpacityProperty, fadeOut);
            };
        }
    }
}