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
            foreach(var file in args)
            {
                if (!File.Exists(file))
                    continue;

                var sym = Sym.Initalize();

                sym.Enum(file);
            }
        }
    }
}
