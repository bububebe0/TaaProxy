using System;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace TaaProxy
{
    internal class ProcessPickerDialog : Window
    {
        public string SelectedProcessName { get; private set; } = "";

        private static readonly Color C_BG   = (Color)ColorConverter.ConvertFromString("#07090F");
        private static readonly Color C_HEAD = (Color)ColorConverter.ConvertFromString("#0B1020");
        private static readonly Color C_BORD = (Color)ColorConverter.ConvertFromString("#1A2640");
        private static readonly Color C_TXT  = (Color)ColorConverter.ConvertFromString("#F0F4FF");
        private static readonly Color C_MUTED= (Color)ColorConverter.ConvertFromString("#4B5A7A");
        private static readonly Color C_ACC  = (Color)ColorConverter.ConvertFromString("#6366F1");
        private static readonly Color C_CARD = (Color)ColorConverter.ConvertFromString("#0D1526");
        private static readonly Color C_SEL  = (Color)ColorConverter.ConvertFromString("#1A2A55");
        private static SolidColorBrush Br(Color c) => new(c);

        private TextBox   _searchBox  = null!;
        private StackPanel _list      = null!;
        private TextBox   _manualBox  = null!;
        private string?   _selected;

        public ProcessPickerDialog()
        {
            Title = "Выбор приложения";
            Width = 480; Height = 520;
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

            Content = BuildContent();
            Loaded += (_, _) => { RefreshList(""); _searchBox.Focus(); };
        }

        private UIElement BuildContent()
        {
            var titleBar = new Border
            {
                Background = Br(C_HEAD), Height = 36,
                BorderBrush = Br(C_BORD), BorderThickness = new Thickness(0, 0, 0, 1)
            };
            var tbGrid = new Grid();
            tbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            tbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var titleText = new TextBlock
            {
                Text = "Выбор запущенного приложения",
                FontSize = 12, FontWeight = FontWeights.SemiBold,
                Foreground = Br(C_MUTED),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(14, 0, 0, 0)
            };
            Grid.SetColumn(titleText, 0);
            tbGrid.Children.Add(titleText);

            var closeBtn = new Button
            {
                Content = "⛌", Width = 40, Height = 36,
                Background = Brushes.Transparent, Foreground = Br(C_MUTED),
                BorderThickness = new Thickness(0), Cursor = Cursors.Hand, FontSize = 11
            };
            closeBtn.MouseEnter += (_, _) => { closeBtn.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444")); closeBtn.Foreground = Brushes.White; };
            closeBtn.MouseLeave += (_, _) => { closeBtn.Background = Brushes.Transparent; closeBtn.Foreground = Br(C_MUTED); };
            closeBtn.Click += (_, _) => DialogResult = false;
            WindowChrome.SetIsHitTestVisibleInChrome(closeBtn, true);
            Grid.SetColumn(closeBtn, 1);
            tbGrid.Children.Add(closeBtn);
            titleBar.Child = tbGrid;

            var body = new Grid { Margin = new Thickness(16, 12, 16, 14) };
            body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            body.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            _searchBox = new TextBox
            {
                Height = 34, FontSize = 14,
                Background = Br((Color)ColorConverter.ConvertFromString("#09090B")),
                Foreground = Br(C_TXT), BorderBrush = Br(C_ACC), BorderThickness = new Thickness(1),
                CaretBrush = Br(C_TXT), Padding = new Thickness(9, 0, 9, 0),
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 8)
            };
            var hint = new TextBlock
            {
                Text = "🔍  Поиск по имени процесса...",
                Foreground = Br(C_MUTED), FontSize = 13, IsHitTestVisible = false,
                VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 0, 0, 0)
            };
            _searchBox.TextChanged += (_, _) =>
            {
                hint.Visibility = _searchBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
                RefreshList(_searchBox.Text);
            };
            var searchGrid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
            searchGrid.Children.Add(_searchBox);
            searchGrid.Children.Add(hint);
            Grid.SetRow(searchGrid, 0);
            body.Children.Add(searchGrid);

            _list = new StackPanel();
            var listScroll = new ScrollViewer
            {
                Content = _list,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = Br(C_CARD),
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };
            var listBorder = new Border
            {
                Child = listScroll,
                BorderBrush = Br(C_BORD), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8),
                Margin = new Thickness(0, 0, 0, 10)
            };
            Grid.SetRow(listBorder, 1);
            body.Children.Add(listBorder);

            var manualLabel = new TextBlock
            {
                Text = "Или введите вручную:",
                FontSize = 12, Foreground = Br(C_MUTED), Margin = new Thickness(0, 0, 0, 4)
            };
            Grid.SetRow(manualLabel, 2);
            body.Children.Add(manualLabel);

            _manualBox = new TextBox
            {
                Height = 34, FontSize = 13,
                Background = Br((Color)ColorConverter.ConvertFromString("#09090B")),
                Foreground = Br(C_TXT), BorderBrush = Br(C_BORD), BorderThickness = new Thickness(1),
                CaretBrush = Br(C_TXT), Padding = new Thickness(8, 0, 8, 0),
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 12)
            };
            _manualBox.KeyDown += (_, e) => { if (e.Key == Key.Enter) CommitManual(); };
            _manualBox.TextChanged += (_, _) =>
            {
                if (!string.IsNullOrWhiteSpace(_manualBox.Text))
                {
                    _selected = null;
                    RefreshListHighlight();
                }
            };
            Grid.SetRow(_manualBox, 3);
            body.Children.Add(_manualBox);

            var btnRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };
            var okBtn = MakeBtn("Добавить", C_ACC);
            okBtn.Click += (_, _) =>
            {
                if (!string.IsNullOrWhiteSpace(_manualBox.Text))
                    CommitManual();
                else if (_selected != null)
                    Commit(_selected);
            };
            var cancelBtn = MakeBtn("Отмена", (Color)ColorConverter.ConvertFromString("#27272A"));
            cancelBtn.Click += (_, _) => DialogResult = false;
            btnRow.Children.Add(okBtn);
            btnRow.Children.Add(cancelBtn);
            Grid.SetRow(btnRow, 4);
            body.Children.Add(btnRow);

            var outer = new DockPanel();
            DockPanel.SetDock(titleBar, Dock.Top);
            outer.Children.Add(titleBar);
            outer.Children.Add(body);
            return outer;
        }

        private void RefreshList(string filter)
        {
            _list.Children.Clear();
            IEnumerable<string> procs = Process.GetProcesses()
                .Where(p => !string.IsNullOrEmpty(p.ProcessName))
                .Select(p => p.ProcessName + ".exe")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n);

            if (!string.IsNullOrWhiteSpace(filter))
                procs = procs.Where(n => n.Contains(filter, StringComparison.OrdinalIgnoreCase));

            bool any = false;
            foreach (var name in procs)
            {
                any = true;
                var n = name;
                var row = new Border
                {
                    Padding = new Thickness(10, 7, 10, 7),
                    CornerRadius = new CornerRadius(6),
                    Cursor = Cursors.Hand,
                    Background = n == _selected
                        ? new SolidColorBrush(C_SEL)
                        : Brushes.Transparent,
                    Margin = new Thickness(4, 2, 4, 2)
                };
                var txt = new TextBlock
                {
                    Text = n, FontSize = 13,
                    Foreground = Br(C_TXT),
                    VerticalAlignment = VerticalAlignment.Center
                };
                row.Child = txt;
                row.MouseLeftButtonDown += (_, e) =>
                {
                    _selected = n;
                    _manualBox.Text = "";
                    if (e.ClickCount >= 2)
                    {
                        Commit(n);
                    }
                    else
                    {
                        RefreshList(_searchBox.Text);
                    }
                };
                _list.Children.Add(row);
            }

            if (!any)
            {
                _list.Children.Add(new TextBlock
                {
                    Text = "Нет совпадений",
                    FontSize = 13, Foreground = Br(C_MUTED),
                    Margin = new Thickness(12, 8, 0, 0)
                });
            }
        }

        private void RefreshListHighlight()
        {
            foreach (var child in _list.Children.OfType<Border>())
            {
                if (child.Child is TextBlock tb)
                    child.Background = tb.Text == _selected
                        ? new SolidColorBrush(C_SEL) : Brushes.Transparent;
            }
        }

        private void CommitManual()
        {
            var v = _manualBox.Text.Trim();
            if (string.IsNullOrEmpty(v)) return;
            SelectedProcessName = v;
            DialogResult = true;
        }

        private void Commit(string name)
        {
            SelectedProcessName = name;
            DialogResult = true;
        }

        private static Button MakeBtn(string text, Color bg)
        {
            const string xaml = @"<ControlTemplate TargetType='Button'
                xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
                xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'>
              <Border x:Name='bd' Background='{TemplateBinding Background}'
                      BorderBrush='{TemplateBinding BorderBrush}'
                      BorderThickness='{TemplateBinding BorderThickness}'
                      CornerRadius='6'>
                <ContentPresenter HorizontalAlignment='Center' VerticalAlignment='Center'/>
              </Border>
            </ControlTemplate>";
            var btn = new Button
            {
                Content = text, Width = 100, Height = 34,
                Margin = new Thickness(0, 0, 8, 0),
                Background = new SolidColorBrush(bg), Foreground = Brushes.White,
                BorderThickness = new Thickness(0), Cursor = Cursors.Hand, FontSize = 13,
                Template = (ControlTemplate)XamlReader.Parse(xaml)
            };
            return btn;
        }
    }
}