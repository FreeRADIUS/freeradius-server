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

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Auto)]
    public struct ValuePair
    {
        public string Name;
        public int ValueType;
        public int ValueLength;
        public System.IntPtr Value;
    }

    public delegate bool Log(int level, string msg);

    public class MainClass
    {
        private static Dictionary<string, int> radiusDictionary = new Dictionary<string, int>();
        private static Log logger;

        // https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshalasattribute.sizeparamindex
        public static void Instantiate(int numberStrings, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex=0)] RadiusString[] strings, Log logger)
        {
            MainClass.logger = logger;

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

        public static void Authenticate()
        {
            logger(radiusDictionary["L_INFO"], "Hello from Authenticate");
        }

        public static void Authorize(int numberValues, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex=0)] ValuePair[] vps)
        {
            foreach (var vp in vps)
            {
                logger(radiusDictionary["L_INFO"], $"{vp.Name} {vp.ValueType} {vp.ValueLength} {vp.Value}");
                byte[] bytes = new byte[vp.ValueLength];
                Marshal.Copy(vp.Value, bytes, 0, bytes.Length);

                if (vp.ValueType == radiusDictionary["PW_TYPE_STRING"])
                {
                    string innerString = System.Text.Encoding.UTF8.GetString(bytes);
                    logger(radiusDictionary["L_INFO"], $"String is {innerString}");
                }
                else if (vp.ValueType == radiusDictionary["PW_TYPE_DATE"])
                {
                    var value = System.BitConverter.ToInt32(bytes, 0);
                    var innerDate = System.DateTimeOffset.FromUnixTimeSeconds(value);
                    logger(radiusDictionary["L_INFO"], $"Date is {innerDate}");
                }
                else if (vp.ValueType == radiusDictionary["PW_TYPE_IPV4_ADDR"])
                {
                    var innerIPAddress = new System.Net.IPAddress(bytes);
                    logger(radiusDictionary["L_INFO"], $"IP address is {innerIPAddress}");
                }
            }
        }
    }
}
