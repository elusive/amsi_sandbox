namespace AmsiSandbox.Tests
{
    using System;
    using System.Threading;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class WindowsDefenderEventServiceFixture
    {
        [TestMethod]
        public void TestWindowsDefenderEventServiceRaisesEvent()
        {
            // arrange
            var raised = false;
            var sut = new WindowsDefenderEventService();
            var wh = new ManualResetEvent(false);
            sut.MalwareAlertEvent += (sender, args) =>
            {
                raised = true;
                sut.ProcessShutdownAction();
                wh.Set();
            };

            // act
            sut.ProcessStartupAction();
            ScanViralString();
            wh.WaitOne(5000);

            // assert
            Assert.IsTrue(raised);
        }

        private void ScanViralString()
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
                out result);

            Assert.AreEqual(AmsiNativeMethods.AMSI_RESULT.AMSI_RESULT_DETECTED, result);

            AmsiNativeMethods.AmsiCloseSession(amsiContext, session);
            AmsiNativeMethods.AmsiUninitialize(amsiContext);
        }
    }
}