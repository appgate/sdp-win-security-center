/**
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

//var test = "{\"product_information\":[{\"product_name\":\"Windows Defender\",\"product_state\":\"On\",\"product_state_timestamp\":\"Mon, 13 May 2019 11:55:00 GMT\",\"product_status\":\"Up-to-date\",\"remediation_path\":\"%ProgramFiles%\\\\Windows Defender\\\\MSASCui.exe\"},{\"product_name\":\"CylancePROTECT\",\"product_state\":\"Off\",\"product_state_timestamp\":\"Sat, 11 May 2019 21:40:30 GMT\",\"product_status\":\"Up-to-date\",\"remediation_path\":\"C:\\\\Program Files\\\\Cylance\\\\Desktop\\\\CylanceSvc.exe\"}],\"provider\":{\"product_count\":2,\"wsc_provider_type\":\"Antivirus\"}}"
var AVJason;

if(!claims.device.avcheck) return false;
var avjsonlit = claims.device.avcheck; //test;

try{
  AVJason = JSON.parse(avjsonlit);
  var avproducts = AVJason["product_information"];
  for (var i = 0; i < avproducts.length; i++){
    var av = avproducts[i];
    // if one of the AV products fulfill, return true
    if( av["product_state"] == "On" && av["product_status"]== "Up-to-date")return true;   
  }
  return false;
} catch(err){
  console.log(err);
  return false;
}