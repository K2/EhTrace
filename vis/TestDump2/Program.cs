using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Dia2Sharp;
using System.IO;

namespace TestDump2
{
    class Program
    {
        static void Main(string[] args)
        {
            List<MinSym> rv = null;
            foreach(var file in args)
            {
                if (!File.Exists(file))
                    continue;

                var sym = Sym.Initalize();

                var len = (ulong) new FileInfo(file).Length;
               
                rv = sym.EnumSymsInFileWithVAOrder(file, 0xbadcafe000000000, len);
            }
            foreach (var r in rv)
            {
                Console.WriteLine(r);
            }
        }
    }
}
