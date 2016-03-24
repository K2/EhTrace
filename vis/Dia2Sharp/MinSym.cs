

namespace Dia2Sharp
{
    public class MinSym
    {
        public string Name;
        public string UDName;
        public ulong Address;
        public ulong Length;
        public uint ID;

        public override string ToString()
        {
            return $"Address [0x{Address:x8}] Length [0x{Length:x4}] Name: [{Name}] UDName: [{UDName}] ID: [{ID}]";
        }

    }
}
