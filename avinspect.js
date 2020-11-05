var AVJason;
if(!claims.device.avinspect) return false;

try{
  	AVJason = JSON.parse(claims.device.avinspect.replace(/\\/g,"").replace(/"{/g,"{").replace(/}"/g,"}").replace(/\r\n/g,""));
  	for (var i = 0; i < AVJason.length; i++){
       var av = AVJason[i];
       if( av["DefinitionStatus"] == "UP_TO_DATE" && av["RealTimeProtectionStatus"]== "ON")return true;   
     }
  	 console.log("required state <> " + state);
  	 return false;
}
catch(err){
 	console.log(err);
 	return false;
}
return false;
