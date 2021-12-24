# volatility_plugins

This repository contains a set of plugins for Volatility 3
These plugins are  *not* compatible with Volatility 2

To use these plugins you will need to use the `-p /path/to/volatility_pugins` as a command line option when running `vol` for specific usages please refer to each individual plugin. 


### Cobaltstrike


#### Configuration Extraction

This plugin will scan all process in active memory for signs of a Cobalt Strike Configuration block, if found it will attempt to parse and extract relevant information. 

We do not render the full configuration only select elements. A future update will expand the presented fields. 

#### Example Usage

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

### Rich Header

This plugin will scan for all runnings proceeses and attempt to recover the rich header. If found the XOR key and the Rich Header Hash will be calculated. 

#### Example Usage

`vol -r pretty -f Server16-CobaltStrike.raw -p ./volatility_plugins/ richheader`

```
Volatility 3 Framework 2.0.0
Formatting...0.00               PDB scanning finished                        
  |  PID |        Process |  XOR Key |                 Rich Header Hash
* |  380 |       smss.exe | e8fbb614 | b4da76d938693e03d2d455ef37561772
* |  512 |      csrss.exe | fba319c1 | e4971216867bfffb7beb058dca378a84
* |  592 |      csrss.exe | fba319c1 | e4971216867bfffb7beb058dca378a84
* |  608 |    wininit.exe | 75318913 | f8116f1336d2c70bd16b01ad8be7bb6d
* |  644 |   winlogon.exe | 4bc258ac | c4f0d2eedff3968a8af33cf724e22790
... SNIP ...
```