using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Agasm;
using Dia2Sharp;


namespace TottsA
{
    /// <summary>
    /// Tott's will merge up Agasm & A* stuff :P~
    /// </summary>
    public class totts
    {

        Dictionary<AModInfo, Agasmic> mi;
        AModInfo ModuleInformation;

        public totts() { }

        public totts(String ModStatsFile, String TraceFile)
        {
            ModuleInformation = new AModInfo();
            ModuleInformation.SetupLoadedModules(ModStatsFile);
            ModuleInformation.SetupTraceData(TraceFile);
        }


        /// <summary>
        /// Takes a while
        /// </summary>
        public void GenSymInfo()
        {
            ModuleInformation.CompileAllSymbolInfo();
            mi = new Dictionary<AModInfo, Agasmic>();
            foreach (var mod in ModuleInformation.LoadedModules)
            {
                mi.Add(mod, new Agasmic(mod.DllPath, mod.Address));
            }
        }


        public IEnumerable<BasicBlock> GetBlocks()
        {
            mi = new Dictionary<AModInfo, Agasmic>();
            foreach (var mod in ModuleInformation.LoadedModules)
                mi.Add(mod, new Agasmic(mod.DllPath, mod.Address));

            foreach (var block in ModuleInformation.uniqD.Values)
            {
                if (block.RIP == 0)
                    continue;

                ModuleInformation.EnsureSymbols(block.RIP);

                // find approp agam
                var gasm = (from ogasm in mi
                           where ogasm.Key.Address <= block.RIP 
                           && 
                           ogasm.Key.Address + ogasm.Key.Length > block.RIP

                            select ogasm.Value).FirstOrDefault();

                if (gasm == null)
                    yield break; 

                yield return gasm.GetBlockFor(block); 


                /*
                if (gasm == null)
                    Console.Write("?? error ??");
                else
                {
                    var compiled = gasm.GetBlockFor(block.RIP);

                    foreach (var line in compiled.Lines)
                        Console.Write(line.Value);

                    Console.WriteLine();
                }
                */
            }
        }
    }
}
