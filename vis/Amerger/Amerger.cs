using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Amerger
{
    public class Amerger
    {
        string inputFile;

        public Amerger(string file)
        {
            inputFile = file;
            
        }

        public bool Parse()
        {
            bool rv = false;

            using (var fs = File.OpenRead(inputFile))
            {
                using (var br = new BinaryReader(fs))
                {
                    int TID = br.ReadInt32();
                    int eflags = br.ReadInt32();
                    ulong rip = br.ReadUInt64();

                }
            }
            return rv;
        }
    }
}
