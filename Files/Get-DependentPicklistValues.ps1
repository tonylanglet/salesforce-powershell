function Get-DependentPicklistValues {
Param(
    $PropertySearch,
    $SObjectName,
    $MainPropertyName
)

[array]$result = @()
$scriptname = "SalesForce Picklist: "

    if($PropertySearch) {
        #region Authenticate to SalesForce
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #Build credential object and SalesForce authentication
            $Token = "<Token>"
            $UserPassword = "<User Password>"
            $Password = "$UserPassword$Token"
            
            $AuthRequest = @{
                Uri = "https://login.salesforce.com/services/oauth2/token"
                Method = "POST"
                ContentType = "application/json"
                $Body = @{
                    grant_type      = "password"
                    client_id       = "<Client_ID>"
                    client_secret   = "<Client_Secret>"
                    username        = "<UserName>"
                    password        = $Password
                }  
            }
            
                  
            try {
                $AuthToken = Invoke-RestMethod @AuthRequest
            } catch {
                Write-Error "$scriptname Unable to retrieve Authentication token, Exception: $_"
            }
        # Auth token generation

        # Get latest version
        $version = (Invoke-RestMethod -URI "$($AuthToken.instance_url)/services/data/" -Method "GET" -Headers @{Authorization = "Bearer $($Authtoken.access_token)"} -ContentType "application/json")[-1].version
        
        #region Request SObject describe
        $Request = @{
            URI = "$($AuthToken.instance_url)/services/data/v$version/sobjects/$SObjectName/describe"
            Method = "GET"
            Headers = @{Authorization = "Bearer $($Authtoken.access_token)"}
            ContentType = "application/json"
        }
        
        try {
            $Response = Invoke-RestMethod @Request
        } catch {
            Write-Error "$scriptname Unable to get SObject"
            throw
        }
        #endregion 
        
        
        $MainObject = ($Response.fields | Where {$_.name -eq $MainPropertyName})
        
        if(![string]::IsNullOrEmpty($MainObject.controllerName) -and $MainObject.picklistValues.count -gt 0) {
        $DependentObject = $Response.fields | Where {$_.name -eq $MainObject.controllerName}  
            
            $Picklist = @()
            foreach ($pValue in $MainObject.picklistvalues) {
                $PicklistObject = New-Object PSObject
                $PicklistObject | Add-Member NoteProperty -Name 'SObject' -Value $MainObject.label
                $PicklistObject | Add-Member NoteProperty -Name 'Label' -Value $pValue.label
                $PicklistObject | Add-Member NoteProperty -Name 'Value' -Value $pValue.value
                $PicklistObject | Add-Member NoteProperty -Name 'Active' -Value $pValue.active
            
            
                if(![string]::IsNullOrEmpty($pValue.validFor)) {
                    $data = $pValue.validFor
            
                    $bitchunk = ""
                    [byte[]]$bitset = [System.Convert]::FromBase64String($data)
                    foreach($bit in $bitset) {
                        $bitChunk += [convert]::ToString([int32]$bit,2).PadLeft(8,'0')            
                    }
            
                    # Get the positions of the Dependent picklist
                    [array]$picklistDependencyPositions = ($bitChunk | Select-String "1" -AllMatches).Matches.Index
            
                    $dependentPicklistArray = @()
                    $dependentPicklistLabelArray = @()
                    foreach($position in $picklistDependencyPositions) {
                        $dependentPicklistArray += $DependentObject.picklistvalues[[int]$position]
                    }
            
                    $PicklistObject | Add-Member NoteProperty -Name 'DependencyPropertyName' -Value $MainObject.controllerName
                    $PicklistObject | Add-Member NoteProperty -Name 'DependencyPropertyValue' -Value $dependentPicklistArray
                }    
                $Picklist += $PicklistObject 
            }
        } else {
            write-host "No controll name or the picklistvalues are empty"
        }
        
        #$PropertySearch = $PropertySearch.Split(",")
        if($PropertySearch.count -gt 0) {
            foreach($prop in $PropertySearch) {
                $PickListItems = $Picklist | Where {$_.label -eq $prop} 
                
                foreach ($pItem in $PickListItems.DependencyPropertyValue) {
                    $result  += [pscustomobject]@{displayname = ($pItem.Label).split("-").Trimstart()[1] ; value = $pItem.Label}
                }
            }
        }
    } else {
        $result += [pscustomobject]@{displayname = 'No value'; value = ''}
    }

$result
}
