using System.Drawing;

namespace TaaProxy
{
    internal class LightProfessionalColorTable : System.Windows.Forms.ProfessionalColorTable
    {
        public override System.Drawing.Color MenuItemBorder => System.Drawing.Color.FromArgb(200, 200, 200);
        public override System.Drawing.Color MenuItemSelected => System.Drawing.Color.FromArgb(230, 230, 230);
        public override System.Drawing.Color MenuItemSelectedGradientBegin => System.Drawing.Color.FromArgb(240, 240, 240);
        public override System.Drawing.Color MenuItemSelectedGradientEnd => System.Drawing.Color.FromArgb(240, 240, 240);
        public override System.Drawing.Color MenuItemPressedGradientBegin => System.Drawing.Color.FromArgb(220, 220, 220);
        public override System.Drawing.Color MenuItemPressedGradientEnd => System.Drawing.Color.FromArgb(220, 220, 220);
        public override System.Drawing.Color MenuBorder => System.Drawing.Color.FromArgb(180, 180, 180);
        public override System.Drawing.Color ImageMarginGradientBegin => System.Drawing.Color.White;
        public override System.Drawing.Color ImageMarginGradientMiddle => System.Drawing.Color.White;
        public override System.Drawing.Color ImageMarginGradientEnd => System.Drawing.Color.White;
        public override System.Drawing.Color ToolStripDropDownBackground => System.Drawing.Color.White;
        public override System.Drawing.Color ToolStripBorder => System.Drawing.Color.FromArgb(180, 180, 180);
        public override System.Drawing.Color MenuStripGradientBegin => System.Drawing.Color.White;
        public override System.Drawing.Color MenuStripGradientEnd => System.Drawing.Color.White;
        public override System.Drawing.Color CheckBackground => System.Drawing.Color.FromArgb(220, 220, 220);
        public override System.Drawing.Color CheckPressedBackground => System.Drawing.Color.FromArgb(200, 200, 200);
        public override System.Drawing.Color CheckSelectedBackground => System.Drawing.Color.FromArgb(200, 200, 200);
        public override System.Drawing.Color ButtonSelectedBorder => System.Drawing.Color.FromArgb(180, 180, 180);
    }
}