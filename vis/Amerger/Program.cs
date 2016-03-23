using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Amerger
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1 || !File.Exists(args[0]))
            {
                Console.WriteLine("Specify the output file from Acleanout.");
                return;
            }
            Console.WriteLine($"Loading file {args[0]}");
            //var am = new Amerger(args[0]);
            

        }






    }
}
