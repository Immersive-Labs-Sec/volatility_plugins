# volatility_plugins

This repository contains a set of plugins for Volatility 3
These plugins are  *not* compatible with Volatility 2

To use these plugins you will need to use the `-p /path/to/volatility_pugins` as a command line option when running `vol` for specific usages please refer to each individual plugin. 


### Cobaltstrike

This plugin has the following components. 

#### Configuration Extraction

This plugin will scan all process in active memory for signs of a Cobalt Strike Configuration block, if found it will attempt to parse and extract relevant information. 

We do not render the full configuration only select elements. A future update will expand the presented fields. 

#### Examples

Scan and output in to JSON format

`vol -r json -f Server16-CobaltStrike.raw -p ./volatility_plugins/ cobaltstrike`

```
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                        
[
  {
    "Jitter": 0,
    "License ID": xxxxxxxxxx,
    "PID": 4396,
    "POST_PATH": "",
    "Pipe": "\\\\.\\pipe\\msagent_89",
    "Port": 4444,
    "Process": "ShellExperienc",
    "Server": "",
    "Sleep": 10000,
    "__children": [],
    "x64 Install_Path": "%windir%\\sysnative\\rundll32.exe",
    "x86 Install_Path": "%windir%\\syswow64\\rundll32.exe"
  },
  {
    "Jitter": 0,
    "License ID": xxxxxxxxxx,
    "PID": 4396,
    "POST_PATH": "",
    "Pipe": "\\\\.\\pipe\\msagent_89",
    "Port": 4444,
    "Process": "ShellExperienc",
    "Server": "",
    "Sleep": 10000,
    "__children": [],
    "x64 Install_Path": "%windir%\\sysnative\\rundll32.exe",
    "x86 Install_Path": "%windir%\\syswow64\\rundll32.exe"
  },
  {
    "Jitter": 0,
    "License ID": xxxxxxxxxx,
    "PID": 4604,
    "POST_PATH": "/submit.php",
    "Pipe": "",
    "Port": 443,
    "Process": "rundll32.exe",
    "Server": "yellowzinc.corp,/ca",
    "Sleep": 5000,
    "__children": [],
    "x64 Install_Path": "%windir%\\sysnative\\rundll32.exe",
    "x86 Install_Path": "%windir%\\syswow64\\rundll32.exe"
  }
]
```

Scan and output in table format

`vol -r pretty -f Server16-CobaltStrike.raw -p ./volatility_plugins/ cobaltstrike`

```
Volatility 3 Framework 2.0.0
Formatting...0.00		PDB scanning finished                        
  |  PID |        Process | Port | Sleep | Jitter |            Server |   POST_PATH |               x86 Install_Path |                x64 Install_Path |                Pipe | License ID
* | 4396 | ShellExperienc | 4444 | 10000 |      0 |                   |             | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe | \\.\pipe\msagent_89 | xxxxxxxxxx
* | 4396 | ShellExperienc | 4444 | 10000 |      0 |                   |             | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe | \\.\pipe\msagent_89 | xxxxxxxxxx
* | 4604 |   rundll32.exe |  443 |  5000 |      0 | yellowzinc.corp,/ca | /submit.php | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe |                     | xxxxxxxxxx
```