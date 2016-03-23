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
using System.Diagnostics;
using Dia2Sharp;


namespace WPFx
{
    public class ModInfo : IComparable, IComparer<ModInfo>
    {
        public string DllPath;
        public ulong Address;
        public uint Length;

        public int CompareTo(object obj)
        {
            if (!(obj is ModInfo))
                return int.MinValue;
            return Address.CompareTo((obj as ModInfo).Address);
        }
        public int Compare(ModInfo x, ModInfo y)
        {
            return x.CompareTo(y);
        }
    }


    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnSymbols_Click(object sender, RoutedEventArgs e)
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

            LoadSymStats(LoadFile);
        }

        void LoadSymStats(string DatFile)
        {
            
            Syms = new HashSet<MinSym>();

            var Modules = GetModInfoSet(DatFile);

            // for each module, enum symbols into Syms List
            if (Modules.Count() > 0)
            {
                // since we have a sorted set of modules
                // the enum should be in VA order also
                // to give us a uniform order
                foreach(var Module in Modules)
                {

                }
            }
        }

        static SortedSet<ModInfo> GetModInfoSet(string ModStatsFile)
        {
            const int rec_size = 1080;
            int pos = 0;

            var Modules = new SortedSet<ModInfo>();

            using (var fs = File.OpenRead(ModStatsFile))
            {
                using (var br = new BinaryReader(fs))
                {
                    var nameArr = new byte[260 * 2];

                    for (int i = 0; i < fs.Length / rec_size; i++)
                    {
                        pos = (i * rec_size);

                        fs.Position = pos + 24;

                        var baseAddr = br.ReadUInt64();
                        var modLen = br.ReadUInt32();

                        fs.Position = pos + 48 + (256 * 2);

                        fs.Read(nameArr, 0, 260 * 2);

                        var aDLLPath = UTF8Encoding.Unicode.GetString(nameArr);

                        Debug.WriteLine($"Reading module Base: [{baseAddr:X}] Length [{modLen:X}] Path: [{aDLLPath}]");
                        Modules.Add(new ModInfo() { DllPath = aDLLPath, Address = baseAddr, Length = modLen });
                    }
                }
            }
            return Modules;
        }




        HashSet<MinSym> Syms;
        SortedSet<ModInfo> Modules;

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

        // waiting for https://github.com/Microsoft/automatic-graph-layout/issues/64 to get fixed :(
        //GraphmapsViewer graphMapsViewer;
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

                    /*
                    graphMapsViewer = new GraphmapsViewer();
                    graphMapsViewer.LayoutEditingEnabled = false;
                    graphMapsViewer.BindToPanel(gvPanel);
                    */

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
                    //graphMapsViewer.Graph = dgraph;

                }
            }
        }

    }
}
