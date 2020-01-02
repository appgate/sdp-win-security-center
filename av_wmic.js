/* 
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
*/   


 /** 
 * Create a on demand device script with the wmicprovider.exe, once for 
 * old OS and newer (Vista/Server 2008 or newer ):
 *      wmicprovider.exe /namespace:\\root\SecurityCenter2 path AntiVirusProduct
 *      wmicprovider.exe /namespace:\\root\SecurityCenter path AntiVirusProduct
 * 
 * 
 * Status interpretation (this can change whenever Microsoft likes to change it)
 * Example: "266240" -- > 41000 -> 041000 -> 04 10 00 :: [Other][product state][AV definition]
 *                        01234    
 * left padded with 0 to 6 digits. However the first two are not used
 * (F/0)E DC BA -- > from the right to the leeft:
 *    BA:: Security Signature Status
 *    DC: Security Product State
 * var av_definition_states = {"00": "UP_TO_DATE",
                               "10": "OUT_OF_DATE"}
 *
 * var product_states = { "00": "OFF",  
                          "01" :"EXPIRED",
                          "10": "ON",
                          "11": "SNOOZED"}  
**/

var av_json;
var productStates =[];
if(!claims.device.wmicavinspect) return false; // test against namespace:\\root\SecurityCenter (<=Windows7)
if(!claims.device.wmicavinspect2) return false; // test against namespace:\\root\SecurityCenter2
//[ { "displayName": "CylancePROTECT", "instanceGuid": "{B0D0C4F4-7F0B-0434-B825-1213C45DAE01}", "pathToSignedProductExe": "C:\\Program Files\\Cylance\\Desktop\\CylanceSvc.exe", "pathToSignedReportingExe": "C:\\Program Files\\Cylance\\Desktop\\CylanceSvc.exe", "productState": 397312, "timestamp": "Mon, 18 Jun 2018 08:42:34 GMT" }, { "displayName": "Windows Defender", "instanceGuid": "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}", "pathToSignedProductExe": "%ProgramFiles%\\Windows Defender\\MSASCui.exe", "pathToSignedReportingExe": "%ProgramFiles%\\Windows Defender\\MsMpeng.exe", "productState": 393472, "timestamp": "Fri, 15 Jun 2018 14:09:56 GMT" } ]
var AVIsActive = "10";
var AVIsUptodate = "00";

function is_qualified(av_claim){
    try{
        av_json = JSON.parse(av_claim);
        for (var i = 0; i < av_json.length; i++){
            // there can be more than 1 AV product installed
            var av = av_json[i];
            var productState = av["productState"];
            var state = productState.toString(16);
            productStates.push(state);
            var AVDevinitionStateCode = state.substring(state.length-2,state.length);
            var productStateCode = state.substring(state.length-4,state.length-2);
            if (productStateCode == AVIsActive && 
                AVDevinitionStateCode == AVIsUptodate) return true;
        }     
        console.log(productStates);
    }
    catch(err){
 		console.log(err);
 		return false;
	}
  return false;
}

if (is_qualified(claims.device.wmicavinspect)) return true;
if (is_qualified(claims.device.wmicavinspect2)) return true;
return false;
