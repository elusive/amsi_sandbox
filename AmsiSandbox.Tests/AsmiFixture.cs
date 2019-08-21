namespace AmsiSandbox.Tests
{
    using System;
    using System.Text;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class AsmiFixture
    {
        [TestMethod]
        public void TestAsmiScanStringReturnsExpectedValue()
        {
            IntPtr amsiContext;
            IntPtr session;
            AmsiNativeMethods.AMSI_RESULT result = 0;
            int returnValue;

            returnValue =
                AmsiNativeMethods.AmsiInitialize("AmsiSandbox",
                    out amsiContext); // appName is the name of calling program
            returnValue = AmsiNativeMethods.AmsiOpenSession(amsiContext, out session);
            returnValue = AmsiNativeMethods.AmsiScanString(amsiContext,
                TestHelper.VIRAL_STRING, "EICAR", session,
                out result); // I've used [EICAR test string](https://en.wikipedia.org/wiki/EICAR_test_file)

            Assert.AreEqual(AmsiNativeMethods.AMSI_RESULT.AMSI_RESULT_DETECTED, result);

            AmsiNativeMethods.AmsiCloseSession(amsiContext, session);
            AmsiNativeMethods.AmsiUninitialize(amsiContext);
        }

        [TestMethod]
        public void TestAsmiScanBufferReturnsExpectedValue()
        {
            var virus = Encoding.UTF8.GetBytes(TestHelper.VIRAL_STRING);

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

            if (hrScan != 0) Assert.Fail($"AmsiScanBuffer failed, HRESULT {hrScan:X8}");

            Assert.AreEqual(AmsiNativeMethods.AMSI_RESULT.AMSI_RESULT_DETECTED, result);
        }
    }
}