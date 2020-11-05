
# Functions
function ConvertTo-Json_legacy($objS) {
    $legacy = '['
    $o_count = 0
    $count = 0
    foreach($obj in $objS){
        if($o_count -ge 1) {
            $legacy += ', {'
        }else {
            $legacy += '{'
        }
        foreach($property in $obj.PsObject.Properties){
            if ($count -ge 1) {
                $format_s = ", `"{0}`": `"{1}`""
            } else {
                $format_s = "`"{0}`": `"{1}`""
            }
            $name_p =  $property.Name
            $value_p = $property.Value
            $element = $format_s -f $name_p, $value_p
            $legacy += $element 
            $count++
        }
        $legacy +=  '}'
       $count = 0
        $o_count ++
    }
    $legacy +=  ']'
    return $legacy
}

function ag_write_result($msg){
     if ($is_modern_psv) {
         $msg = ConvertTo-Json $msg -Compress
    } else {
        $msg = ConvertTo-Json_legacy $msg 
    }
    Write-Output $($msg)
}


# End functions

Set-StrictMode -Version Latest
$Computer="localhost"
$results =  @()
$errors =  @()
    Try 
    {   
        

        $psversion = [int]$PSversionTable.PSVersion.Major
        IF ( $psversion -ge 3 )  
        { 
           $is_modern_psv = $true
        }  
        Else  
        { 
            $is_modern_psv = $false
        }


        [system.Version]$OSVersion = (Get-WmiObject win32_operatingsystem -computername $Computer).version 

        IF ($OSVersion -ge [system.version]'6.0.0.0')  
        { 
            # Write-Verbose "OS Windows Vista/Server 2008 or newer detected." 
            $AntiVirusProduct_r = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $Computer -ErrorAction Stop 
        }  
        Else  
        { 
            # Write-Verbose "Windows 2000, 2003, XP detected"  
            $AntiVirusProduct_r = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop 
        } # end IF ($OSVersion -ge 6.0)  

        if ($AntiVirusProduct_r) { 
            <# 
            it appears that if you convert the productstate to HEX then you can read the 1st 2nd or 3rd block  
            to get whether product is enabled/disabled and whether definitons are up-to-date or outdated 
            #> 
            $AntiVirusProduct = @()
            if ($AntiVirusProduct_r -is [array] ){
                $AntiVirusProduct = $AntiVirusProduct_r
            } else{
                $AntiVirusProduct += $AntiVirusProduct_r
            }
            try{
                for ($i=0; $i -lt $AntiVirusProduct.length; $i++) {
                    $productState = $AntiVirusProduct[$i].productstate
                    # convert to hex, add an additional '0' left if necesarry
                    $hex = [Convert]::ToString($productState, 16).PadLeft(6,'0') 
                
                    
                    # Substring(int startIndex, int length)   
                    # 39 75 68
                    # 01 23 45
                    $WSC_SECURITY_PROVIDER = $hex.Substring(0,2) 
                    $WSC_SECURITY_PRODUCT_STATE = $hex.Substring(2,2) 
                    $WSC_SECURITY_SIGNATURE_STATUS = $hex.Substring(4,2) 


                    #n ot used yet 
                    $SECURITY_PROVIDER = switch ($WSC_SECURITY_PROVIDER) 
                    { 
                        0  {"NONE"} 
                        1  {"FIREWALL"} 
                        2  {"AUTOUPDATE_SETTINGS"} 
                        4  {"ANTIVIRUS"} 
                        8  {"ANTISPYWARE"} 
                        16 {"INTERNET_SETTINGS"} 
                        32 {"USER_ACCOUNT_CONTROL"} 
                        64 {"SERVICE"} 
                        default {"UNKNOWN"} 
                    } 


                    $RealTimeProtectionStatus = switch ($WSC_SECURITY_PRODUCT_STATE) 
                    { 
                        "00" {"OFF"}  
                        "01" {"EXPIRED"} 
                        "10" {"ON"} 
                        "11" {"SNOOZED"} 
                        default {"UNKNOWN"} 
                    } 

                    $DefinitionStatus = switch ($WSC_SECURITY_SIGNATURE_STATUS) 
                    { 
                        "00" {"UP_TO_DATE"} 
                        "10" {"OUT_OF_DATE"} 
                        default {"UNKNOWN"} 
                    } 

                    $AV = $Null 
                    $AV = New-Object -TypeName PSObject -ErrorAction Stop -Property @{ 
                        ComputerName = $env:computername; 
                        Name = $AntiVirusProduct[$i].displayName; 
                        ProductExecutable = $AntiVirusProduct[$i]; 
                        DefinitionStatus = $DefinitionStatus; 
                        RealTimeProtectionStatus = $RealTimeProtectionStatus; 
                        ProductState = $productState; 
                        #ComputerDateTime = $formatteddate = "{0:h:mm:ss tt zzz}" -f (get-date);
                    
                     } | Select-Object ComputerName,Name,DefinitionStatus,RealTimeProtectionStatus,ProductState   
                    $results += $AV
                }  
          
                <#   
                # Switch to determine the status of antivirus definitions and real-time protection. 
                # The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx 
                switch ($AntiVirusProduct.productState) { 
                        #AVG Internet Security 2012 (from antivirusproduct WMI) 
                        "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
                        "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 

                        "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
                        "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
                        "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
                        "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
                        "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
                        "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
                        "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
                        #Windows Defender 
                        "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}  
                        "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
                        "397568" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 

                        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"} 
                    } 
                #> 



                # Output PSCustom Object 
                 
            }
            Catch{
                $errorMessage = New-Object -TypeName PSObject -ErrorAction Stop -Property @{
                    Exception = ($error[0].Exception | out-string);
                    ScriptName = $MyInvocation.MyCommand.Name;
                    ComputerName = $env:computername;
                    #ComputerDateTime = $formatteddate = "{0:h:mm:ss tt zzz}" -f (get-date);
                    PsVersion = [string]$PSversionTable.PSVersion
                }
                $errors += $errorMessages
                return
            }

            
            }else {
                $results = New-Object -TypeName PSObject -ErrorAction Stop -Property @{ 
                    ComputerName =$env:computername; 
                    Name = "No av detected." 
                    ProductExecutable = "n/a"; 
                    DefinitionStatus = "n/a"; 
                    RealTimeProtectionStatus = "n/a" 
                    ProductState = "n/a"; 
                    #ComputerDateTime = $formatteddate = "{0:h:mm:ss tt zzz}" -f (get-date);
                    PsVersion = [string]$PSversionTable.PSVersion
                } 
        }
        ag_write_result $results
    } 
    Catch  
    { 
        $errorMessage = New-Object -TypeName PSObject -ErrorAction Stop -Property @{
            Exception = ($error[0].Exception | out-string);
            ScriptName = $MyInvocation.MyCommand.Name;
            ComputerName = $env:computername;
            #ComputerDateTime = $formatteddate = "{0:h:mm:ss tt zzz}" -f (get-date);
            PsVersion = [string]$PSversionTable.PSVersion
        }
        $errors += $errorMessage
        ag_write_result $errors
    }                               



