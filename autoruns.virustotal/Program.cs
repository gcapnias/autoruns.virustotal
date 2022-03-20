using System;

namespace autoruns.virustotal
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            string textStream = null;

            if (Console.IsInputRedirected)
            {
                textStream = Console.In.ReadToEnd();
                Console.Out.WriteLine("Console is redirected!\r\n\r\n");
                Console.Out.WriteLine(textStream);
            }
            else
            {
                Console.Out.WriteLine("Console is not redirected!\r\n");
            }

        }
    }
}
