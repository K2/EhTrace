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
        public ulong TSC;

        public ulong CycleCount;

        public AStepEvent() { }

        public AStepEvent(BinaryReader br)
        {
            Flags = br.ReadUInt32();
            var aTID = br.ReadUInt32();
            var aRIP = br.ReadUInt64();
            var aRSP = br.ReadUInt64();
            var aFROM_RIP = br.ReadUInt64();

            TSC =   ((aTID & 0xffff0000) >> 16) |               
                    ((aRIP & 0xffff000000000000) >> 32) |
                    ((aRSP & 0xffff000000000000) >> 16) |
                    (aFROM_RIP & 0xffff000000000000);

            TID = aTID & ~0xffff0000;
            RIP = aRIP & ~0xffff000000000000;
            RSP = aRSP & ~0xffff000000000000;
            FROM_RIP = aFROM_RIP & ~0xffff000000000000;

            CycleCount = 1;
        }

        public override string ToString() => $"RSP [{RSP:X}] RIP [{RIP:X}] FROM_RIP [{FROM_RIP:X}]";
    }
}
