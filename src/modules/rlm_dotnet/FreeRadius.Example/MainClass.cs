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
        // https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshalasattribute.sizeparamindex
        public static void Instantiate(int numberStrings, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex=0)] RadiusString[] strings, Log logger)
        {
            logger(4, "Hello from Instantiate");
            logger(5, $"strings.Length = {strings.Length}");
            foreach (var _string in strings)
            {
                logger(3, $"{_string.Name} = {_string.Value}");
            }
        }
    }
}
