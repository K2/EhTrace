using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dia2Sharp
{
    public class AModInfo : IComparable, IComparer<AModInfo>
    {
        public SortedSet<AModInfo> LoadedModules;
        public Dictionary<ulong, AStepEvent> uniqD;
        List<string> LoadedMods;

        public Sym SymCtx;

        public string DllPath;
        public ulong Address;
        public uint Length;

        public AModInfo()
        {
            LoadedMods = new List<string>();
            SymCtx = Sym.Initalize();
            uniqD = new Dictionary<ulong, AStepEvent>();
        }

        public void SetupLoadedModules(string ModStatsFile)
        {
            LoadedModules = GetModInfoSet(ModStatsFile);
        }
        public void SetupTraceData(string TraceDataFile)
        {
            uniqD = LoadTraceData(TraceDataFile);
        }

        /// <summary>
        /// This would be nice if we could Parallel.Task it
        /// </summary>
        public void CompileAllSymbolInfo()
        {
            foreach (var mod in LoadedModules)
            {
                if(!mod.DllPath.ToLower().Contains("ehtrace"))
                    Sym.ListAllSymbols.Concat(SymCtx.EnumSymsInFileWithVAOrder(mod.DllPath, mod.Address, mod.Length));
            }
        }

        public void EnsureSymbols(ulong Address)
        {
            var Module = (from mod in LoadedModules
                          where Address >= mod.Address && Address < mod.Address + mod.Length
                          select mod).FirstOrDefault();

            if (Module == null)
                return;

            if (Module.Address != 0 && !LoadedMods.Contains(Module.DllPath))
                Sym.ListAllSymbols.Concat(SymCtx.EnumSymsInFileWithVAOrder(Module.DllPath, Module.Address, Module.Length));

            LoadedMods.Add(Module.DllPath);
        }

        public int CompareTo(object obj)
        {
            if (!(obj is AModInfo))
                return int.MinValue;
            return Address.CompareTo((obj as AModInfo).Address);
        }
        public int Compare(AModInfo x, AModInfo y)
        {
            return x.CompareTo(y);
        }

        static SortedSet<AModInfo> GetModInfoSet(string ModStatsFile)
        {
            const int rec_size = 1080;
            int pos = 0;

            var Modules = new SortedSet<AModInfo>();

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

                        //Debug.WriteLine($"Reading module Base: [{baseAddr:X}] Length [{modLen:X}] Path: [{aDLLPath}]");
                        Modules.Add(new AModInfo() { DllPath = aDLLPath, Address = baseAddr, Length = modLen });
                    }
                }
            }
            return Modules;
        }

        /// <summary>
        /// This will give us a pretty basic graph and dump a lot of context out to avoid a monster set of links
        /// I plan to render a column in the disassembly view which indicates the count of passes for a given block
        /// so you can see hot paths etc...
        /// </summary>
        /// <param name="DatFile"></param>
        /// <returns></returns>
        public static Dictionary<ulong, AStepEvent> LoadTraceData(string DatFile)
        {
            var uniqD = new Dictionary<ulong, AStepEvent>();

            using (var fs = File.OpenRead(DatFile))
            {
                using (var br = new BinaryReader(fs))
                {
                    while (fs.Position < fs.Length)
                    {
                        var se = new AStepEvent(br);

                        if (!uniqD.ContainsKey(se.FROM_RIP))
                            uniqD.Add(se.FROM_RIP, se);
                        else
                            uniqD[se.FROM_RIP].CycleCount++;
                    }
                }
            }
            return uniqD;
        }
    }
}
