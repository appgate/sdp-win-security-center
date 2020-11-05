/**
* You can test it in a condition, by either using a existing session, or a hard-coded
* test string (see var test). Make sure you use a string that you generated from one
* of your client machines running the agwscapi.exe. Assure you it is escaped properly 
* referring to the example, or copying from a user-session for which you deployed the 
* device script with agwscapi.exe.
*/

//var test = "{ \"Antivirus\": [ { \"product_name\": \"Windows Defender\", \"product_state\": \"Off\", \"product_status\": \"Up-to-date\", \"remediation_path\": \"%ProgramFiles%\\\\Windows Defender\\\\MSASCui.exe\" }, { \"product_name\": \"CylancePROTECT\", \"product_state\": \"On\", \"product_status\": \"Up-to-date\", \"remediation_path\": \"C:\\\\Program Files\\\\Cylance\\\\Desktop\\\\CylanceSvc.exe\" } ] }"
var AVJason;

if(!claims.device.avcheck) return false;
var avjsonlit = claims.device.avcheck; 
//var avjsonlit = test;

try{
  AVJason = JSON.parse(avjsonlit);
  var avproducts = AVJason["Antivirus"];
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
