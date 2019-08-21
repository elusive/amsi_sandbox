namespace AmsiSandbox
{
    using System;

    public interface IWindowsDefenderEventService
    {
        event EventHandler<MalwareAlertEventArgs> MalwareAlertEvent;
    }
}