## Disclaimer
© 2019, AppGate, Inc.  All rights reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: (a) redistributions
of source code must retain the above copyright notice, this list of conditions and
the disclaimer below, and (b) redistributions in binary form must reproduce the
above copyright notice, this list of conditions and the disclaimer below in the
documentation and/or other materials provided with the distribution.
THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN “AS IS” BASIS AND
YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  APPGATE DISCLAIMS ALL
EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION OF LAW, STATUTORY
OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL WARRANTIES OF MERCHANTABILITY,
TITLE, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, ACCURACY, COMPLETENESS,
COMPATABILITY OF SOFTWARE OR EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.
APPGATE DOES NOT WARRANT THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.
IN NO EVENT SHALL APPGATE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
RELIANCE, EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL,
LOSS OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF PROFITS,
REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR REDISTRIBUTION OF
SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY UNDER WHICH SUCH LIABILITY
IS ASSERTED AND REGARDLESS OF WHETHER APPGATE HAS BEEN ADVISED OF THE POSSIBILITY
OF SUCH LIABILITY.

# Overview
This material demonstrates the use case of device scripting. We encourage you are familiar with the [AppGate Extension](https://appgate.github.io/appgate-extensions/).

In this use case we enforce user security based on the status of the end user's antivirus product running on the client machine (OS.
The basic idea is to create a posture check:
1. retrieve the AV status on the OS, ship it to AppGate
2. AppGate makes a decision based on the expected values for the relevant outcomes

The outcomes can be policy assignment, a condition in an entitlement or entitlement script.

The code and examples are based on Windows operating systems.  The  state of the antivirus product is retrieved and sent to AppGate. The script interacts with the Windows Security Center to query the state. The script uses the WMI method from the operating system. Please refer to the attached PowerShell script for a functional description.

In the below section we demonstrate how it can be used block or allow traffic from an entitlement: 
    If any of the users AV is `up to date` and has `real time protection` enabled, the traffic in an entitlement is allowed, otherwise blocked.

The information regarding AV is retrieved from `Windows Security Center`, and we rely on the result it delivers. There is not much documentation revealed by Microsoft regarding interaction with Windows Security Center and it's reporting. The return codes might be subject to change, so it's up to the implementer (customer) to assure proof for validity of the codes. Please refer to the script for more details.

## Methods
There are two methods presented which are slightly different but produce the same result:
1. Using the [avinspect.ps1](./avinspect.ps1) as the device script and the [avinspect.js](./avinspect.js) as the evaluation logic.
2. Using the [WSCapi.exe](https://github.com/appgate/appgate-avcheck/releases/latest) as the device script, and the [av_wscapi.js](av_wscapi.js) as the evaluation logic.
3. Using the [wmicprovider.exe]() as the device script, and the [av_mic.js](./av_mic.js) as the evaluation logic.


The pros&cons are discussed below.

## Method 1: powershell script
The script returns readable status information, translated from the Windows Security Center's status codes. The script always returns a JSON script. An example of a retrieved state in AppGate looks like the following: 

```json
[
    {
        "ComputerName": "DESKTOP-VP9DEAD",  
        "Name": "Windows Defender",  
        "ProductExecutable": "%ProgramFiles%\\Windows Defender\\MSASCui.exe",  
        "DefinitionStatus": "UP_TO_DATE",  
        "RealTimeProtectionStatus": "SNOOZED", 
        "ProductState": 397568 
    }
]
```

### Upload the powershell script
_Scripts > Device Scripts_
Upload the script to the AppGate server under the section "scripts > device scripts".  

### Map a New On-Demand Device Claim
_System > Identity Providers > `edit the appropriate identity provider> Map On-demand Device Claims> Add new_ 
* Select `Run Device Script`.
* Device script > choose the previously uploaded one.
* Device Script: avinspect.ps1
* Arguments: (leave empty)
* Claim Name: avinspect
* Platform: All Windows Devices

### Create a condition
_operations > Condition > Add New_
In the new condition in `Assignment` click on `Switch to Editor mode`. I these part we now consume the JSON from the device claim which will be stored in a claim called `claims.device.avinspect`. Copy to code from the avinspect.js in there.

Add a user notification (remedy:reason) for the case when the condition fails. For example: A user is denied access because AppGate could not detect your antivirus status, or it fails the condition. 
Example for user notification: 
    Access denied: Install the antivirus, ensure it's running, and ensure its virus definition is up to date.

#### Entitlement
Attach the condition the the entitlement(s) you want to enforce the check.

## Method 2: using the wscapi (the proper way) 

Targets: 
* Windows 8 and upwards
* Desktop only / 64bit

The method has the same setup as in method 3: an executable which collects the infomration and the JS to be the consumer and decision maker within appgate

Benefits:
* The exe uses the Windows Security Center API, and we do not need to be concerned with the inner states, it is properly documented.
* You don't need to set an execution policy for PS scripts.
* Maintenance and simplicity on the device: Logic is kept in condition, where it is most flexible and central administrated.

The cons are:
* You are dependend on AppGate Inc.: if `wscapi` changes on one of their OSs we need to do that too.
* If you really have pre Windows 8 machines or 32bit, you need to treat those seperatly.
* You need to white list it on the end point.

### wscapi.exe
You find it on it's dedicated repository:
* [WSCApi.exe](https://github.com/appgate/appgate-avcheck/releases/latest) 
* SHA256: `2812f87004b6ff8d9a4c2513e3b44f578092a8404684a7b0baf1fc9025fe497d`


### Upload the Device Script
 
* Upload the WSCApi.exe. Windows 32-bit machines are not supported.
* Create a new device claims mappings with WSCAPI with the arguments for Windows:

```json
"claimName": "avcheck",
"command": "runScript",
"parameters": {
    "args": "-av",
    "name": "wscapi"
}
```



### Create conditions
* copy paste the condition [av_wscapi.js](./av_wscapi.js) and copy the content into a condition. Make any adjustment if needed.
 
Check that you use the claims name in the code that you used when creating the on-demand device claims.

### Entitlement
 Attach the condition to the wanted entitlement.


## Method 3: wmic provider (alternative method)
The result will be the same as the above; but instead, you use an executable to collect the information required, and then do the state and status interpretation in the condition, whereas in the powershell variant we interpret status in the ps script.

This has these benefits:
* You don't need to set an execution policy for PS scripts.
* Maintenance and simplicity on the device: Logic is kept in condition. If Microsoft updates internal states, it is handled in the AppGate Console and doesn't require a PS change.
* Doesn't need a PowerShell environment, used when an organization has different versions and different OS versions.

The cons are:
* You need to have a device script for Windows 7 and older one for >Windows 7. 
* Both always need to run where W7 is a user device. There is no selector yet in device claim mappings--the selection is only Windows.*all*.
* 32-bit machines are not supported by the .exe.

### wmicprovider
You find it on it's dedicated repository:
* [latest release](https://github.com/appgate/appgate-wmicprovider) 


### Upload the Device Script
 
* Upload the wmicprovider.exe. Windows 32-bit machines are not supported.
* Create two (2) new device claims mappings with wmicprovider with these arguments for Windows:
```shell
    /namespace:\\root\SecurityCenter path AntiVirusProduct —> claim name: wmicavinspect
    /namespace:\\root\SecurityCenter2 path AntiVirusProduct —> claim name: wmicavinspect2
```
 See above steps for method 1 how to map device claims.


### Create conditions
* copy paste the condition [av_wmic.js](./av_wmic.js) and copy the content into a condition.
 
Check that you use the claims name in the code that you used when creating the on-demand device claims.

### Entitlement
 Attach the condition to the wanted entitlement.


