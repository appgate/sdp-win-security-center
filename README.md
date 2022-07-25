# Overview
This material demonstrates the use case of device scripting. We encourage you are familiar with the [Appgate Extension](https://github.com/appgate/sdp-extensions/).
>Note: the example shows a how-to for anti-virus, however you will be able to do the same for firewall and anti-spyware

In this use case we enforce user security based on the status of the end user's antivirus product running on the client machine (OS.
The basic idea is to create a posture check:
1. retrieve the AV status on the OS, ship it to Appgate
2. Appgate makes a decision based on the expected values for the relevant outcomes

The outcomes can be policy assignment, a condition in an entitlement or entitlement script.

The code and examples are based on Windows operating systems.  The  state of the antivirus product is retrieved and sent to Appgate. The script interacts with the Windows Security Center to query the state. The script uses the WMI method from the operating system. Please refer to the attached PowerShell script for a functional description.

In the below section we demonstrate how it can be used block or allow traffic from an entitlement: 
    If any of the users AV is `up to date` and has `real time protection` enabled, the traffic in an entitlement is allowed, otherwise blocked.

The information regarding AV is retrieved from `Windows Security Center`, and we rely on the result it delivers. There is not much documentation revealed by Microsoft regarding interaction with Windows Security Center and it's reporting. The return codes might be subject to change, so it's up to the implementer (customer) to assure proof for validity of the codes. Please refer to the script for more details.

## Methods
1. Using the [avinspect.ps1](./avinspect.ps1) as the device script and the [avinspect.js](./avinspect.js) as the evaluation logic.
2. Deprecated method due to deprecating `wmic` in a coming Windows 11 version.

## Powershell method (AV only)
The script returns readable status information, translated from the Windows Security Center's status codes. The script always returns a JSON script. An example of a retrieved state in Appgate looks like the following: 

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
Upload the script to the Appgate server under the section "scripts > device scripts".  

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
In the new condition in `Access Criteria` click on dropdown next to `Allowed when` select `script returns true`. I these part we now consume the JSON from the device claim which will be stored in a claim called `claims.device.avinspect`. Copy to code from the avinspect.js in there.

Add a user notification (remedy:reason) for the case when the condition fails. For example: A user is denied access because Appgate could not detect your antivirus status, or it fails the condition. 
Example for user notification: 
    Access denied: Install the antivirus, ensure it's running, and ensure its virus definition is up to date.

#### Entitlement
Attach the condition the entitlement(s) you want to enforce the check.


## The deprecated method: using the wscapi 
>Note this method can be used for other security providers such as `Firewall` and `Antispyware`.
See the dedicated repository for more information and the exe [sdp-wscapi](https://github.com/appgate/sdp-wscapi).

The method has an executable which collects the information on the device. A JavaScript expression will then allow to parse the returned information and design the logic for it. 

Benefits:
* The exe uses the Windows Security Center API, and we do not need to be concerned with the inner states, it is properly documented.
* You don't need to set an execution policy for PS scripts.
* Maintenance and simplicity on the device: Logic is kept in condition, where it is most flexible and central administrated.

The cons are:
* You are dependent on Appgate Inc.: if `wscapi` changes on one of their operating systems, we need to do that too.
* If you really have pre Windows 8 machines or 32bit, you need to treat those separately.
* You need to white list it on the end point.

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
 
 
