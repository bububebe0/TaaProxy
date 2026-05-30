using System;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using TaaProxy.Views;

namespace TaaProxy
{
    internal class TrayDropZone : Window
    {
        private readonly MainWindow _owner;
        private static readonly string[] _proxySchemes =
            { "vless://", "hysteria2://", "hy2://", "ss://", "trojan://", "vmess://", "tuic://", "hysteria://" };

        private static readonly Color C_BG   = (Color)ColorConverter.ConvertFromString("#0B1020");
        private static readonly Color C_ACC  = (Color)ColorConverter.ConvertFromString("#6366F1");
        private static readonly Color C_TXT  = (Color)ColorConverter.ConvertFromString("#F0F4FF");
        private static readonly Color C_MUTED= (Color)ColorConverter.ConvertFromString("#4B5A7A");
        private static SolidColorBrush Br(Color c) => new(c);

        private Border _border = null!;

        public TrayDropZone(MainWindow owner)
        {
            _owner = owner;

            Title = "Taa Drop Zone";
            Width = 130; Height = 80;
            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;
            Background = Brushes.Transparent;
            Topmost = true;
            ResizeMode = ResizeMode.NoResize;
            ShowInTaskbar = false;
            FontFamily = new FontFamily("Segoe UI");

            var wa = SystemParameters.WorkArea;
            Left = wa.Right - Width - 12;
            Top  = wa.Bottom - Height - 12;

            _border = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(225, 11, 16, 32)),
                BorderBrush = Br(C_ACC),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Cursor = Cursors.Arrow
            };

            var sp = new StackPanel
            {
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            sp.Children.Add(new TextBlock
            {
                Text = "🔗",
                FontSize = 22,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 4, 0, 0)
            });
            sp.Children.Add(new TextBlock
            {
                Text = "Бросить ссылку",
                FontSize = 10,
                Foreground = Br(C_MUTED),
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 4)
            });
            _border.Child = sp;
            Content = _border;

            AllowDrop = true;
            DragEnter += OnDragEnter;
            DragLeave += OnDragLeave;
            Drop += OnDrop;

            MouseLeftButtonDown += (_, _) => DragMove();
            MouseRightButtonDown += (_, _) => Hide();
        }

        private bool HasLinks(IDataObject d)
        {
            string text = "";
            if (d.GetDataPresent(DataFormats.UnicodeText))
                text = d.GetData(DataFormats.UnicodeText) as string ?? "";
            else if (d.GetDataPresent(DataFormats.Text))
                text = d.GetData(DataFormats.Text) as string ?? "";
            return _proxySchemes.Any(s => text.Contains(s, StringComparison.OrdinalIgnoreCase))
                || (d.GetDataPresent(DataFormats.FileDrop) &&
                    (d.GetData(DataFormats.FileDrop) as string[])?.Any(f =>
                        f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)) == true);
        }

        private void OnDragEnter(object sender, DragEventArgs e)
        {
            if (HasLinks(e.Data))
            {
                e.Effects = DragDropEffects.Copy;
                _border.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981"));
                _border.Background  = new SolidColorBrush(Color.FromArgb(200, 8, 28, 18));
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void OnDragLeave(object sender, DragEventArgs e)
        {
            _border.BorderBrush = Br(C_ACC);
            _border.Background  = new SolidColorBrush(Color.FromArgb(225, 11, 16, 32));
        }

        private void OnDrop(object sender, DragEventArgs e)
        {
            _border.BorderBrush = Br(C_ACC);
            _border.Background  = new SolidColorBrush(Color.FromArgb(225, 11, 16, 32));

            var links = MainWindow.ExtractDropLinks(e.Data);
            if (links.Count > 0)
                _owner.ImportDroppedLinks(links);
            e.Handled = true;
        }
    }
}