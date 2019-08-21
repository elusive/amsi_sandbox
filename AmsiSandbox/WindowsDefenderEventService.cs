namespace AmsiSandbox
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.Eventing.Reader;
    using System.Linq;
    using System.Xml;

    public class WindowsDefenderEventService : IDisposable, IWindowsDefenderEventService
    {
        private const string AvEventsQueryText = @"*[System/Provider/@Name=""Microsoft-Windows-Windows Defender""]";
        private EventLogWatcher _watcher;

        public void Dispose()
        {
            _watcher?.Dispose();
        }

        public event EventHandler<MalwareAlertEventArgs> MalwareAlertEvent;

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