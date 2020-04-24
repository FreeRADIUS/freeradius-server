using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace FreeRadius.Example
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Auto)]
    public struct RadiusString
    {
        public string Name;
        public int Value;
    }

    public delegate bool Log(int level, string msg);

    public class MainClass
    {
        private static Dictionary<string, int> radiusDictionary = new Dictionary<string, int>();

        // https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshalasattribute.sizeparamindex
        public static void Instantiate(int numberStrings, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex=0)] RadiusString[] strings, Log logger)
        {
            // Build the dictionary from the strings sent down
            foreach (var element in strings)
            {
                if (element.Name != null)
                {
                    radiusDictionary.Add(element.Name, element.Value);
                }
            }

            logger(radiusDictionary["L_ERR"], "Hello from Instantiate");
            logger(radiusDictionary["L_WARN"], $"strings.Length = {strings.Length}");
            foreach (var _string in strings)
            {
                logger(radiusDictionary["L_INFO"], $"{_string.Name} = {_string.Value}");
            }
        }
    }
}
