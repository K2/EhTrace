using System;
using System.IO;

namespace Amerger
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2 || !File.Exists(args[0]) || !File.Exists(args[1]))
            {
                Console.WriteLine("Specify the output file from Acleanout.");
                return;
            }
            Console.WriteLine($"Loading trace file {args[0]}, modstats file {args[1]}");
            //var am = new Amerger(args[0]);
        }
    }
    
    // Aboot merges and get's symbols glued into the dissassembly
    public class Aboot
    {
        public string Atracefile;
        public string Amodstats;

        public Aboot(string atrace, string amods)
        {
            Atracefile = atrace;
            Amodstats = amods;
        }


        /// <summary>
        /// Load symbols for all modules as required.
        /// 
        /// </summary>
        public void Initalize()
        {







        }





    }
}
