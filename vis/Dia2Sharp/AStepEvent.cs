using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dia2Sharp
{
    public class AStepEvent
    {
        public uint TID;
        public uint Flags;
        public ulong RIP;
        public ulong RSP;
        public ulong FROM_RIP;

        public ulong CycleCount;

        public AStepEvent() { }

        public AStepEvent(BinaryReader br)
        {
            TID = br.ReadUInt32();
            Flags = br.ReadUInt32();
            RIP = br.ReadUInt64();
            RSP = br.ReadUInt64();
            FROM_RIP = br.ReadUInt64();
            CycleCount = 1;
        }
    }
}
