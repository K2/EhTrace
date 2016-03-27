using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TottsA;
using System.IO;
using Dia2Sharp;

namespace AStackFolding
{
    class Program
    {
        // 1Million!
        const int MAX_LINES = (100 * 100);

        Dictionary<uint, List<AStepEvent>> Threaded;

        void Run(string DatFile)
        {
            Threaded = new Dictionary<uint, List<AStepEvent>>();
            AStepEvent first = null, last = null;
            long lcnt = 0;

            using (var fs = File.OpenRead(DatFile))
            {
                using (var br = new BinaryReader(fs))
                {
                    while (fs.Position < fs.Length)
                    {
                        lcnt++;
                        if(first == null)
                            first = new AStepEvent(br);
                        else
                            last = new AStepEvent(br);

                        /*
                        if (!Threaded.ContainsKey(se.TID))
                            Threaded.Add(se.TID, new List<AStepEvent>());

                        Threaded[se.TID].Add(se);
                        */
                    }
                }
            }

            //var primary_thr = Threaded.Values.OrderByDescending(x => x.Count()).FirstOrDefault();

            Console.WriteLine(
                $"Total events {lcnt} StartTSC = {first.TSC:X} LastTSC = {last.TSC:X} Span = {(last.TSC - first.TSC):X}");

#if FALSE
            var counts = from se in primary_thr
            group se by se.RSP into grouped
            select new { RSP = grouped.Key, SE = primary_thr.Find((x) => x.RSP == grouped.Key), Count = grouped.Count() };
            
            // fold stacks
            AStepEvent tfind = primary_thr.First();
            AStepEvent last = null;
            StringBuilder sb = new StringBuilder();
            int i = 0;
            int line_cnt = 0;
            Stack<AStepEvent> sEvetnts = new Stack<AStepEvent>();

            foreach (var se in primary_thr)
            {
                if(sEvetnts.Count() == 0 || se.RSP < sEvetnts.Peek().RSP)
                    sEvetnts.Push(se);
                else
                {
                    int cnt = sEvetnts.Count();
                    foreach (var sx in sEvetnts)
                        sb.Append($"Code{sx.RIP:X};");

                    sb.AppendLine($" {(counts.Where((xcnt) => xcnt.RSP == se.RSP).FirstOrDefault()).Count}");
                    //sb.AppendLine($"x\t{cnt}");
                    Console.Write(sb.ToString());
                    sEvetnts.Pop();
                    line_cnt++;
                }

                if (line_cnt >= MAX_LINES)
                    return;
                
                /*

                sb.Append($"a{se.RIP:X}");
                i++;
                if (se.RSP < tfind.RSP || (last != null && last.RSP < se.RSP))
                {
                    // sb.AppendLine($" {(counts.Where((cnt) => cnt.RSP == se.RSP).FirstOrDefault()).Count}");
                    sb.Append($" {i}\r\n");
                    Console.Write(sb.ToString());
                    sb = new StringBuilder();
                    tfind = se;
                    i = 0;
                    last = null;
                }
                else
                    sb.Append(";");
                last = se;
                */
            }
#endif
            Console.WriteLine("Done.");
        }


        static void Main(string[] args)
        {
            new Program().Run(args.First());
        }
    }
}
