using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using Microsoft.Msagl.Core.DataStructures;
using Microsoft.Msagl.Core.Layout.ProximityOverlapRemoval;
using Microsoft.Msagl.Core.Layout.ProximityOverlapRemoval.MinimumSpanningTree;
using Microsoft.Msagl.Core.Routing;
using Drawing = Microsoft.Msagl.Drawing;
using Microsoft.Msagl.Layout.Incremental;
using Microsoft.Msagl.Layout.LargeGraphLayout;
using Microsoft.Msagl.Layout.Layered;
using Microsoft.Msagl.Layout.MDS;
using Microsoft.Msagl.GraphmapsWpfControl;
using Microsoft.Msagl.WpfGraphControl;

namespace WPFx
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnLoad_Click(object sender, RoutedEventArgs e)
        {
            var LoadFile = string.Empty;
            var ofd = new OpenFileDialog
            {
                Filter = "(*.*)|*.*",
                FilterIndex = 1,
                RestoreDirectory = true,
                Multiselect = false
            };

            if (ofd.ShowDialog() == true)
                LoadFile = ofd.FileName;

            if (string.IsNullOrWhiteSpace(LoadFile))
                return;

            LoadData(LoadFile);

        }

        GraphmapsViewer graphMapsViewer;
        GraphViewer graphViewer;

        Dictionary<long, long> uniqD;

        void LoadData(string DatFile)
        {
            uniqD = new Dictionary<long, long>();

            using (var fs = File.OpenRead(DatFile))
            {
                using (var br = new BinaryReader(fs))
                {

                    graphViewer = new GraphViewer();
                    graphViewer.LayoutEditingEnabled = false;
                    graphViewer.BindToPanel(gvPanel);

                    var dgraph = new Drawing.Graph();
                    Drawing.Edge edg = null;

                    while (fs.Position < fs.Length - 128)
                    {
                        var tid = br.ReadInt32();
                        var flags = br.ReadInt32();
                        var rip = br.ReadInt64();
                        var rsp = br.ReadInt64();
                        var from_rip = br.ReadInt64();

                        if (!uniqD.ContainsKey(from_rip))
                        {
                            uniqD.Add(from_rip, rip);
                            edg = dgraph.AddEdge(from_rip.ToString("X"), rip.ToString("X"), rip.ToString("X"));
                        }
                    }

                    graphViewer.Graph = dgraph;


                }
            }
        }

    }
}
