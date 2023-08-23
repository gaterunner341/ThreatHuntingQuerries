T1176: Browser Extensions Loaded via Shortcut

CrowdStrike
```
event_platform=win CommandLine IN (*--load-extension*) NOT (*[known exclusion]*)
| eval CommandLine=lower(CommandLine)
| eval CommandLine=replace(CommandLine,"program files\\\\google\\\\chrome\\\\application\\\\chrome.exe","CHROMEPATH")
| eval CommandLine=replace(CommandLine,"program files \(x86\)\\\\google\\\\chrome\\\\application\\\\chrome.exe","CHROMEPATH")
| eval CommandLine=replace(CommandLine,"program files\\\\microsoft\\\\edge\\\\application\\\\msedge.exe","EDGEPATH")
| eval CommandLine=replace(CommandLine,"program files \(x86\)\\\\microsoft\\\\edge\\\\application\\\\msedge.exe","EDGEPATH")
| eval CommandLine=replace(CommandLine,"users\\\\[^\\\\]+","users\\USERNAME")
| eval CommandLine=replace(CommandLine,"scoped\_dir[0-9]+\_[0-9]+","USERDATADIRECTORY")
| stats dc(ComputerName) count by CommandLine
| sort + count
```

Splunk
```
sourcetype=WinEventLog EventCode=4688 Process_Command_Line IN (*--load extension)
| stats dc(ComputerName) by Process_Command_Line
```