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
            $URI = "https://login.salesforce.com"
            $auth_Username = Get-APSetting IglooUsername
            $auth_ClientSecret = Get-APSetting IglooClientSecret
            $auth_Token = Get-APSetting IglooToken
            $auth_ClientID = Get-APSetting IglooClientID
            $auth_ServiceAccount = Get-ServiceAccount -Name $auth_Username -Scope 2
            $auth_ServicePassword = $auth_ServiceAccount.Password #| ConvertTo-SecureString -AsPlainText -Force
            $auth_granttype = "password"
            
            $auth_Password = "$auth_ServicePassword$auth_Token"
            $authURI = "$URI/services/oauth2/token"
                
            $authBody = @{
                grant_type=$auth_GrantType
                client_id=$auth_ClientID
                client_secret=$auth_ClientSecret
                username=$auth_Username
                password=$auth_Password
            }  
                  
            try {
                $AuthToken = Invoke-RestMethod -Uri $authURI -Method POST -Body $authBody
            } catch {
                Write-Error "$scriptname Unable to retrieve Authentication token, Exception: $_"
            }
        # Auth token generation

        
        #region Request SObject describe
        $Request = @{
            URI = "$($AuthToken.instance_url)/services/data/v20.0/sobjects/$SObjectName/describe"
            Method = "GET"
            Headers = @{Authorization = "Bearer $($Authtoken.access_token)"}
            ContentType = "application/json"
        }
        
        try {
            $Response = Invoke-RestMethod @Request
        } catch {
            Write-Error "$scriptname Unable to get SObject"
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
                        #$dependentPicklistLabelArray += $DependentObject.picklistvalues[[int]$position].label
                        $dependentPicklistLabelArray += ($DependentObject.picklistvalues[[int]$position].label).split("-").Trimstart()[1] # Snow Specific
                    }
            
                    $PicklistObject | Add-Member NoteProperty -Name 'DependencyPropertyName' -Value $MainObject.controllerName
                    $PicklistObject | Add-Member NoteProperty -Name 'DependencyPropertyValue' -Value $dependentPicklistArray
                    $PicklistObject | Add-Member NoteProperty -Name 'DependencyPropertyLabelValue' -Value $dependentPicklistLabelArray
                          
                    #write-host "$($pValue.label) $bitChunk" -ForegroundColor Green
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
                
                foreach ($plItem in $PickListItems.DependencyPropertyValue) {
                
                    write-host "$scriptname adding dependent picklist items $($plItem)"
                    #$result += $_.DependencyPropertyLabelValue
                    $result  += [pscustomobject]@{displayname = ($plItem.Label).split("-").Trimstart()[1] ; value = $plItem.Label}
                }
            }
        }
    } else {
        $result += [pscustomobject]@{displayname = 'No value'; value = ''}
    }

$result
}
