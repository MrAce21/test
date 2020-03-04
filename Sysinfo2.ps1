[CmdletBinding()]
param
(
  [string]$varCDH = $( Read-Host -Prompt 'Enter CDH Number' ),
  [switch]$xml,
  [string]$computerName = $env:COMPUTERNAME
)

function Get-CPUs
{
  [CmdletBinding()]
  param
  (
    [String]$computerName = $env:COMPUTERNAME
  )
    
  try
  {
    $processors = Get-WmiObject -Query 'SELECT Name,NumberOfCores,SocketDesignation FROM Win32_Processor' -Namespace 'root/CIMV2' -ComputerName $computerName
    # Get-WmiObject -ComputerName $computerName -Class win32_processor
    
    if (@($processors)[0].NumberOfCores)
    {
      $cores = @($processors).count * @($processors)[0].NumberOfCores
    }
    else
    {
      $cores = @($processors).count
    }
    
    if ($processors.name.count -gt 1)
    {
      $procname = $processors.name[0]
    }
    else
    {
      $procname = $processors.name
    }
    
    $sockets    = @(@($processors) |
      ForEach-Object -Process {
        $_.SocketDesignation
      } |
    Select-Object -Unique).count
    
    #('Cores: {0}, Sockets: {1}' -f $cores, $sockets)
    
    $CPUs       = New-Object -TypeName PSObject -Property @{
      'Cores' = $cores
      'Sockets' = $sockets
      'Name'  = $procname
    }
    return $CPUs
  }
  catch
  {
    Write-Error -Message "Error on fetching CPU information for host $computerName.  Function Get-CPUs threw: $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Error -Message "Error was in Line $line"
  }
}

function Test-IsDC
{
  [CmdletBinding()]
  param 
  (
    [string]$computerName = $env:COMPUTERNAME
  )

  try
  {
    $DomainRole = Get-WmiObject -ComputerName $computerName -Class Win32_ComputerSystem -Property DomainRole | Select-Object -ExpandProperty DomainRole
  
    if ($DomainRole -eq 5)
    {
      return [Bool]1
    }
    else 
    {
      return [Bool]0
    }
  }
  catch
  {
    Write-Error -Message "Error on testing for domain controller.  Function Test-IsDC threw: $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Error -Message "Error was in Line $line"
  }
}

function Get-DomainRole
{
  [CmdletBinding()]
  param(
    [int]$type
  )
  process
  {
    $role = DATA
    {
      ConvertFrom-StringData -StringData @'
  0 = Standalone Workstation
  1 = Member Workstation
  2 = Standalone Server
  3 = Member Server
  4 = Backup Domain Controller
  5 = Primary Domain Controller
'@
    }
    $role[('{0}' -f ($type))]
  }
}

function Get-IPv4Addr
{
  [CmdletBinding()]
  param
  (
    [string]$computerName = $env:COMPUTERNAME
  )
  
  $ipaddr = @([Net.Dns]::GetHostByName($computerName).AddressList)
  return $ipaddr.IPAddressToString
}

function Get-HostList
{
  process
  {
    $ErrorActionPreference = 'SilentlyContinue'
    if (-not(Get-Command -Name Get-ADComputer))
    {
      Write-Warning -Message "ActiveDirectory Module is not present or loaded on $computerName.  Continuing in Single-Host mode."
      return $env:COMPUTERNAME
    }
    try
    {
      #Import-Module -Name .\bin\Microsoft.ActiveDirectory.Management.dll
      $ComputerList = @()
      $Computers    = @()
      $ComputerList = Get-ADComputer -Filter 'OperatingSystem -like "Windows*Server*"'-Properties Name | Select-Object -ExpandProperty Name
      foreach ($computer in $ComputerList) 
      {
        if (Test-Connection -ComputerName $computer -Quiet -Count 1)
        {
          if (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer)
          {
            $Computers = $Computers += $computer
          }
        }
      }
    }    
    catch
    {
      Write-Error -Message "Error compiling host list.  Function Get-Hostlist threw: $_"
      $line = $_.InvocationInfo.ScriptLineNumber
      Write-Error -Message "Error was in Line $line"
    }
    return $Computers
  }
}

function Invoke-SQLquery
{
  [CmdletBinding()]
  param
  (
    [string]$computerName = '.',
    [string]$Database = 'master',
    [string]$Query = $null,
    [int]$QueryTimeout = 10
  )
  try
  {
    if ($Total.IsPresent)
    {
      $Query = 'SELECT CONVERT(DECIMAL(10,2),(SUM(size * 8.00) / 1024.00 / 1024.00)) As UsedSpace FROM master.sys.master_files'
    }    
    $conn                  = New-Object -TypeName System.Data.SqlClient.SQLConnection
    $conn.ConnectionString = 'Server={0};Database={1};Integrated Security=True' -f $computerName, $Database
    $conn.Open()
    $cmd                   = New-Object -TypeName system.Data.SqlClient.SqlCommand -ArgumentList ($Query, $conn)
    $cmd.CommandTimeout    = $QueryTimeout
    $ds                    = New-Object -TypeName system.Data.DataSet
    $da                    = New-Object -TypeName system.Data.SqlClient.SqlDataAdapter -ArgumentList ($cmd)
    $null                  = $da.fill($ds)
    $ds.Tables[0]
    $conn.Close()
  }
  catch
  {
    Write-Error -Message "Error in SQL query to host $computerName.  Function Invoke-SQLquery threw: $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Error -Message "Error was in Line $line"
  }
}

function Test-SqlSvr
{
  [CmdletBinding()]
  param 
  (
    [string]$computerName = $env:COMPUTERNAME
  )
    
  $IsSql = Get-Service -ComputerName $computerName  | Where-Object -FilterScript {
    ($_.name -like "MSSQL$*" -or $_.name -like 'MSSQLSERVER' -or $_.name -like 'SQL Server (*')
  }
  if ($IsSql) 
  {
    return [Bool]1
  }
  else 
  {
    return [Bool]0
  }
}

function Test-IsPM 
{
  [CmdletBinding()]
  param
  (
    [String]$computerName
  )
    
  $varpmRegKey = 'SOFTWARE\\Wow6432Node\\CompuSense\\NtierHealth\\StandardSettings'
  $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computerName)
  $regkey = $null
  $regkey = $reg.OpenSubKey($varpmRegKey)

  if(-not($regkey))
  {
    return [Bool]0
  }
  else
  {
    return [Bool]1
  }
}

function Test-IsEHR 
{
  [CmdletBinding()]
  param
  (
    [String]$computerName
  )
    
  $varehrRegKey = 'SOFTWARE\\Wow6432Node\\HealthMatics'
  $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computerName)
  $regkey = $null
  $regkey = $reg.OpenSubKey($varehrRegKey)

  if(-not($regkey))
  {
    return [Bool]0
  }
  else
  {
    return [Bool]1
  }
}

function Test-IsRDS
{
  [CmdletBinding()]
  param ([string]$computerName)

  $varIsRDP = Get-WmiObject -Query 'SELECT TerminalServerMode FROM Win32_TerminalServiceSetting' -Namespace 'root/CIMV2/TerminalServices' -ComputerName $computerName -Authentication 6
    
  if($varIsRDP.TerminalServerMode -eq 1)
  {
    return [string]'Y'
  }
}

function Convert-Bytes
{
  [CmdletBinding()]
  param ([long]$bytes,
    [switch]$togb,
  [switch]$tomb)
  
  try
  {
    if ($togb)
    {
      $gibibytes = [math]::Round($bytes/1024/1024/1024)
      return $gibibytes
    }
    else
    {
      $mebibytes = [math]::Round($bytes/1024/1024)
      return $mebibytes
    }
  }
  catch
  {
    Write-Error -Message "Error on byte conversion calculation on $computerName. Function Convert-Bytes threw: $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Error -Message "Error was in Line $line"
  }
}
  
function Get-Disks
{
  [CmdletBinding()]
  param ([string]$computerName)
  
  try
  {
    $varDiskArray = @()
  
    $varDiskData = Get-WmiObject -ComputerName $computerName -Query "SELECT * FROM Win32_LogicalDisk WHERE DriveType = '3'"
      
    foreach ($disk in $varDiskData)
    {
      $varDiskArray = $varDiskArray += $disk.DeviceID, $disk.Size, $disk.FreeSpace
    }
    Return $varDiskArray
  }
  catch
  {
    Write-Error -Message "Error on fetching disk information for host $computerName.  Function Get-Disks threw: $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Error -Message "Error was in Line $line"
  }
}
    
function Convert-EhrVersion
{
  [CmdletBinding()]
  param(
    [string]$version
  )
  process
  {
    $release = DATA
    {
      ConvertFrom-StringData -StringData @'
  200.2 = 18.2 GA
  201.0 = 19.1 GA
  201.1 = 19.1.1
  201.2 = 19.1.2
  202.2 = 19.3 GA
  202.3 = 19.3.1
  203.0 = 19.4 GA
  204.0 = 20.1 GA
'@
    }
    $release[('{0}' -f ($version))]
  }
}
  

################################################ START MAIN SCRIPT ##########################################################


$varDate                 = Get-Date -Format 'yyyy-MM-dd'
$varTime                 = Get-Date -Format "HH:mm:ss G'M'Tzzz"
$varFnameUID             = Get-Date -Format 'yyMMdd-HHmm'
$resultsArray            = [Collections.ArrayList]@()
$OutputFilename          = ('{0}-{1}-SysReport' -f $varFnameUID, $varCDH)
$ErrorActionPreference   = 'SilentlyContinue'


if (Test-IsDC)
{
  $hosts = Get-HostList
  ('{0} hosts detected' -f $hosts.count)
}
else
{
  Write-Warning -Message "$env:COMPUTERNAME is not a domain controller, continuing in Single-Server mode."
  $hosts = $env:COMPUTERNAME
}

ForEach ( $computerName in $hosts ) 
{
  $varCPU         = $null
  $varBios        = Get-WmiObject -Query 'SELECT SerialNumber FROM Win32_BIOS' -Namespace 'root/CIMV2' -ComputerName $computerName
  $varCompSys     = Get-WmiObject -Query 'SELECT Domain,DomainRole,Manufacturer,Model,Name,TotalPhysicalMemory FROM Win32_ComputerSystem' -Namespace 'root/CIMV2' -ComputerName $computerName
  $varDisk       = Get-Disks -computerName $computerName
  $varCPU        = Get-CPUs -computerName $computerName
  $varOS         = Get-WmiObject -Query 'SELECT Caption FROM Win32_OperatingSystem' -Namespace 'root/cimv2' -ComputerName $computerName
  $varIPv4addr   = Get-IPv4Addr -ComputerName $computerName
  $varDomainRole = Get-DomainRole -type $varCompSys.DomainRole
  $varIsRDS      = Test-IsRDS -ComputerName $computerName
  $varIsSQL      = Test-SqlSvr -ComputerName $computerName
  $varSQLVersion = $null
  $varSqlDbSize  = $null
  $varArraySQL   = $null
  $varPMver      = $null
  $varEHRver     = $null 
  
  if ($varIsSQL)
  {
    $varSQLVersion = $null
    $varArraySQL = @()
    $varSqlDbSize  = @()
    $varArraySQL = Invoke-SQLquery -ComputerName $computerName -Query 'sp_SERVER_INFO'
    $varSqlDbSize  = Invoke-SQLquery -ComputerName $computerName -Query 'SELECT CONVERT(DECIMAL(10,2),(SUM(size * 8.00) / 1024.00 / 1024.00)) As UsedSpace FROM master.sys.master_files'
    $varSQLVersion = $varArraySQL.attribute_value[1]
        
    if (Test-IsPM -computername $computerName)
    {
      $varPMver = Invoke-SQLquery -ComputerName $computerName -Database 'Ntier_10000' -Query 'SELECT TOP 1 Version FROM PM.ntier_version ORDER BY Update_Date DESC'
    }
  
    if (Test-IsEHR -computername $computerName)
    {
      $varEHRver = Invoke-SQLquery -ComputerName $computerName -Database 'EMR' -Query 'SELECT TOP 1 VERSIONNUMBER FROM HPSITE.TASK'
      $varEHRver = $varEHRver.VERSIONNUMBER.Substring(0,5)
      $varEHRver = Convert-EhrVersion -version $varEHRver
    }
  }
  
  $currentRecord = New-Object -TypeName PSObject -Property @{
    'CDH #'          = $($varCDH)
    'Datestamp'      = $($varDate)
    'Timestamp'      = $($varTime)
    'System Name'    = $($varCompSys.name)
    'Service Tag'    = $($varBios.SerialNumber)
    'Manufacturer'   = $($varCompSys.Manufacturer)
    'Model'          = $($varCompSys.Model)
    'IP Address'     = $($varIPv4addr)
    'Domain'         = $($varCompSys.Domain)
    'Domain Role'    = $($varDomainRole)
    'RDS Server'     = $($varIsRDS)
    'CPU Type'       = $($varCPU.Name)
    'Core Count'     = $($varCPU.Cores)
    'CPU Count'      = $($varCPU.Sockets)
    'RAM (GB)'       = $(Convert-Bytes $varCompSys.TotalPhysicalMemory -togb)
    'OS'             = $($varOS.Caption)
    'SQL Version'    = $($varSQLVersion)
    'SQL DB Size (GB)' = $($varSqlDbSize.UsedSpace)
    'EHR Version'    = $($varEHRver)
    'PM Version'     = $($varPMver.version)
    'Disk0'          = $($varDisk[0])
    'Size0'          = $(Convert-Bytes $varDisk[1] -togb)
    'Free0'          = $(Convert-Bytes $varDisk[2] -togb)
    'Disk1'          = $($varDisk[3])
    'Size1'          = $(Convert-Bytes $varDisk[4] -togb)
    'Free1'          = $(Convert-Bytes $varDisk[5] -togb)
    'Disk2'          = $($varDisk[6])
    'Size2'          = $(Convert-Bytes $varDisk[7] -togb)
    'Free2'          = $(Convert-Bytes $varDisk[8] -togb)
    'Disk3'          = $($varDisk[9])
    'Size3'          = $(Convert-Bytes $varDisk[10] -togb)
    'Free3'          = $(Convert-Bytes $varDisk[11] -togb)
    'Disk4'          = $($varDisk[12])
    'Size4'          = $(Convert-Bytes $varDisk[13] -togb)
    'Free4'          = $(Convert-Bytes $varDisk[14] -togb)
  }
  $resultsArray.Add( $currentRecord ) > $null
}

$varPropertyList = 'CDH #', 'Datestamp', 'Timestamp', 'System Name', 'Service Tag', 'Manufacturer', 'Model', 'IP Address', 'Domain', 'Domain Role', 'RDS Server', 'CPU Type', 'Core Count', 'CPU Count', 'RAM (GB)', 'OS', 'SQL Version', 'SQL DB Size (GB)', 'EHR Version', 'PM Version', 'Disk0', 'Size0', 'Free0', 'Disk1', 'Size1', 'Free1', 'Disk2', 'Size2', 'Free2', 'Disk3', 'Size3', 'Free3', 'Disk4', 'Size4', 'Free4'

if ($xml.IsPresent)
{
  $resultsArray.ToArray() |
  Select-Object -Property $varPropertyList |
  Export-Clixml -Path $OutputFilename'.xml'
}
else 
{
  $resultsArray.ToArray() |
  Select-Object -Property $varPropertyList |
  Export-Csv -Path $OutputFilename'.csv' -NoTypeInformation
}
