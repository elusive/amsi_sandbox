namespace AmsiSandbox.Tests
{
    using System;
    using System.Threading;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class WindowsDefenderEventServiceFixture
    {
        [TestMethod]
        public void TestWindowsDefenderEventServiceSetScheduleTime()
        {
            // arrange
            const int minutesPastMidnight = 123;
            var sut = new WindowsDefenderEventService();

            // act
            sut.ProcessStartupAction();
            var succeeded = sut.SetScanScheduleTime(minutesPastMidnight);

            // assert
            Assert.IsTrue(succeeded);
        }

        [TestMethod]
        public void TestWindowsDefenderEventServiceReadsLogs()
        {
            // arrange
            var to = new DateTimeOffset(DateTime.Now.AddDays(1));
            var from = new DateTimeOffset(DateTime.Now.AddDays(-3));
            var sut = new WindowsDefenderEventService();

            // act
            sut.ProcessStartupAction();
            ScanViralString();
            var loggedEvent = sut.GetLogsByDateRange(from, to).ReadEvent();

            // assert
            Assert.IsNotNull(loggedEvent);
            Assert.AreEqual("Microsoft-Windows-Windows Defender", loggedEvent.ProviderName);

            sut.ProcessShutdownAction();
        }

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