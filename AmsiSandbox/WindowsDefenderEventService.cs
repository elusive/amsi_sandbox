namespace AmsiSandbox
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Eventing.Reader;
    using System.IO;
    using System.Linq;
    using System.Threading.Tasks;
    using System.Xml;
    using GroupPolicyCom;
    using Microsoft.Win32;

    public class WindowsDefenderEventService : IDisposable
    {
        private const string AvEventsQueryText = @"*[System/Provider/@Name=""Microsoft-Windows-Windows Defender""]";
        private EventLogWatcher _watcher;

        public void Dispose()
        {
            _watcher?.Dispose();
        }

        public event EventHandler<MalwareAlertEventArgs> MalwareAlertEvent;

        public bool SetScanScheduleTime(int minutesPastMidnight)
        {
            try
            {
                var gpo = new ComputerGroupPolicyObject();

                using (var machine = gpo.GetRootRegistryKey(GroupPolicySection.Machine))
                {
                    using (var scheduleTimeKey =
                        machine.CreateSubKey(GroupPolicyPaths.WindowsDefenderScanTimeOfDayScheduled))
                    {
                        scheduleTimeKey?.SetValue(GroupPolicyPaths.ScheduleTimeKeyName, minutesPastMidnight,
                            RegistryValueKind.DWord);
                    }
                }

                gpo.Save();

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }

        public async Task ExecuteQuickScan()
        {
            var pathToScanner =
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), 
                    "Windows Defender", 
                    "mpcmdrun.exe");

            await Task.Run(() =>
            {
                using (var proc = new Process())
                {
                    proc.StartInfo.UseShellExecute = false;
                    proc.StartInfo.FileName = pathToScanner;
                    proc.StartInfo.CreateNoWindow = true;
                    proc.Start();
                    proc.WaitForExit();
                }
            });
        } 

        public EventLogReader GetLogsByDateRange(DateTimeOffset @from, DateTimeOffset to)
        {
            try
            {
                var qry = new EventLogQuery(
                    "Microsoft-Windows-Windows Defender/Operational",
                    PathType.LogName,
                    $"*[System[TimeCreated[@SystemTime >= '{from.ToUniversalTime().ToString("o")}' and @SystemTime <= '{to.ToUniversalTime().ToString("o")}']]]");
                var rdr = new EventLogReader(qry);
                return rdr;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        public void ProcessStartupAction()
        {
            Subscribe();
        }

        public void ProcessShutdownAction()
        {
            Dispose();
        }

        private void Subscribe()
        {
            try
            {
                var subscribeQuery = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational",
                    PathType.LogName, AvEventsQueryText);
                _watcher = new EventLogWatcher(subscribeQuery);
                _watcher.EventRecordWritten += EventRecordWrittenHandler;
                _watcher.Enabled = true;
            }
            catch (EventLogReadingException e)
            {
                Console.WriteLine("Error reading the log: {0}", e.Message);
            }
        }

        private void EventRecordWrittenHandler(object obj, EventRecordWrittenEventArgs args)
        {
            if (args.EventRecord == null) return; // error reading the event data

            // create XPath query strings for data we need from the event xml
            var xPathQueries = new string[11];
            xPathQueries[0] = "Event/System/EventID";
            xPathQueries[1] = "Event/System/TimeCreated/@SystemTime";
            xPathQueries[2] = "Event/EventData/Data[@Name=\"Severity ID\"]";
            xPathQueries[3] = "Event/EventData/Data[@Name=\"Severity Name\"]";
            xPathQueries[4] = "Event/EventData/Data[@Name=\"Category ID\"]";
            xPathQueries[5] = "Event/EventData/Data[@Name=\"Category Name\"]";
            xPathQueries[6] = "Event/EventData/Data[@Name=\"Detection User\"]";
            xPathQueries[7] = "Event/EventData/Data[@Name=\"Action ID\"]";
            xPathQueries[8] = "Event/EventData/Data[@Name=\"Action Name\"]";
            xPathQueries[9] = "Event/EventData/Data[@Name=\"Error Code\"]";
            xPathQueries[10] = "Event/EventData/Data[@Name=\"Error Description\"]";

            var selector = new EventLogPropertySelector(xPathQueries.AsEnumerable());
            var eventLogRecord = (EventLogRecord) args.EventRecord;
            var propertyValues = eventLogRecord.GetPropertyValues(selector);

            RaiseMalwareAlertEvent(propertyValues, eventLogRecord.ToXml());
        }

        private void RaiseMalwareAlertEvent(IList<object> values, string xml)
        {
            var xmldoc = new XmlDocument();
            xmldoc.LoadXml(xml);
            var args = new MalwareAlertEventArgs(values, xmldoc.DocumentElement);
            MalwareAlertEvent?.Invoke(this, args);
        }
    }
}