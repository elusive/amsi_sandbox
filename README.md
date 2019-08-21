# Project
This is a sandbox project that uses the Windows 10 AMSI (Anti-malware Scan Interface)
and the .NET EventLogWatcher and EventLogReader.

# Build Status
[![Build Status](https://travis-ci.com/elusive/amsi_sandbox.svg?branch=master)](https://travis-ci.com/elusive/amsi_sandbox)

# Features
The key features or tasks that are accomplished by this code are:
    - Uses AMSI to scan a string or buffer using Windows Defender
    - Allows setting the time for the scheduled quick scan
    - Allows execution of a quick scan using Windows Defender
    - Supports Event reading by date range for Windows Defender logs