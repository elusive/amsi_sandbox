using System;

namespace AmsiSandbox
{
    public static class AmsiNativeMethods
    {
        public enum AMSI_RESULT
        {
            AMSI_RESULT_CLEAN = 0,
            AMSI_RESULT_NOT_DETECTED = 1,
            AMSI_RESULT_DETECTED = 32768
        }

        [DllImport("Amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)]string appName, out IntPtr amsiContext);

        [DllImport("Amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]   
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("Amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]   
        public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("Amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]   
        public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("Amsi.dll", EntryPoint = "AmsiScanString", CallingConvention = CallingConvention.StdCall)]   
        public static extern int AmsiScanString(IntPtr amsiContext, [InAttribute()] [MarshalAsAttribute(UnmanagedType.LPWStr)]string @string, [InAttribute()] [MarshalAsAttribute(UnmanagedType.LPWStr)]string contentName, IntPtr session, out AMSI_RESULT result);

        [DllImport("Amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]   
        public static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, ulong length, string contentName, IntPtr session, out AMSI_RESULT result);   
        
        //This method apparently exists on MSDN but not in AMSI.dll (version 4.9.10586.0)   
        [DllImport("Amsi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]   
        public static extern bool AmsiResultIsMalware(AMSI_RESULT result);

        

        private void CallAmsiUsingScanBuffer()
        {
            var virus = Encoding.UTF8.GetBytes(BAD_STRING);

            IntPtr context;
            var hrInit = AmsiInitialize("AmsiTest", out context);
            if (hrInit != 0)
            {
                Console.WriteLine($"AmsiInitialize failed, HRESULT {hrInit:X8}");
                return;
            }

            AMSI_RESULT result;
            var hrScan = AmsiScanBuffer(
                context, virus, (uint)virus.Length,
                "EICAR Test File", IntPtr.Zero, out result
            );

            AmsiUninitialize(context);

            if (hrScan != 0)
            {
                Console.WriteLine($"AmsiScanBuffer failed, HRESULT {hrScan:X8}");
            }
            else if (result == AMSI_RESULT.AMSI_RESULT_DETECTED)
            {
                Console.WriteLine("Detected EICAR test");
            }
            else
            {
                Console.WriteLine($"Failed to detect EICAR test, result {result:X8}");
            }
        }
    }
}