using System;
using System.Collections;


namespace Dia2Sharp
{
    public class MinSym : IComparable, IComparable<MinSym>
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

        public int CompareTo(object obj)
        {
            var other = obj as MinSym;
            return (Address <= other.Address && ((Address + Length) > other.Address) ? 0 : Address.CompareTo(other.Address));
        }

        public int CompareTo(MinSym other)
        {
            return CompareTo(other);
        }
    }
}
