namespace AmsiSandbox
{
    using System;
    using System.Text;

    internal class Program
    {
        public const string BAD_STRING = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        private static void Main(string[] args)
        {
            var virus = Encoding.UTF8.GetBytes(BAD_STRING);

            IntPtr context;
            var hrInit = AmsiNativeMethods.AmsiInitialize("AmsiTest", out context);
            if (hrInit != 0)
            {
                Console.WriteLine($"AmsiInitialize failed, HRESULT {hrInit:X8}");
                return;
            }

            AmsiNativeMethods.AMSI_RESULT result;
            var hrScan = AmsiNativeMethods.AmsiScanBuffer(
                context, virus, (uint) virus.Length,
                "EICAR Test File", IntPtr.Zero, out result
            );

            AmsiNativeMethods.AmsiUninitialize(context);

            if (hrScan != 0)
                Console.WriteLine($"AmsiScanBuffer failed, HRESULT {hrScan:X8}");
            else if (result == AmsiNativeMethods.AMSI_RESULT.AMSI_RESULT_DETECTED)
                Console.WriteLine("Detected EICAR test");
            else
                Console.WriteLine($"Failed to detect EICAR test, result {result:X8}");

            Console.WriteLine("Hit any key to quit...");
            Console.Read();
        }
    }
}