using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CustomSkinLoader;

namespace CustomWadLoader
{
    class Program
    {
        static void Main(string[] args)
        {
            WadLoader.AddWadFile(@"Champions/Anivia.wad");
            while(true)
                System.Threading.Thread.Sleep(1);
        }
    }
}
