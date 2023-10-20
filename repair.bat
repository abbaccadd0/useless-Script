@echo off
chcp 65001

@REM 开始获取管理员权限
setlocal
set uac=~uac_permission_tmp_%random%
md "%SystemRoot%\system32\%uac%" 2>nul
if %errorlevel%==0 ( rd "%SystemRoot%\system32\%uac%" >nul 2>nul ) else (
    echo set uac = CreateObject^("Shell.Application"^)>"%temp%\%uac%.vbs"
    echo uac.ShellExecute "%~s0","","","runas",1 >>"%temp%\%uac%.vbs"
    echo WScript.Quit >>"%temp%\%uac%.vbs"
    "%temp%\%uac%.vbs" /f
    del /f /q "%temp%\%uac%.vbs" & exit )
@REM ============


@REM 安全
@REM ============
@REM 注意：你需要想办法关闭Windows Denfeder，才能让这部分的一些内容生效:(
@REM 使用最新.NETFramework
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework" /v "OnlyUseLatestCLR" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" /v "OnlyUseLatestCLR" /t REG_DWORD /d 00000001 /f
@REM 关闭幽灵、熔断、DownFall
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 33554435 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
@REM 关闭基于虚拟化的安全
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0 /f
bcdedit.exe /set vsmlaunchtype off
bcdedit.exe /set hypervisorlaunchtype off
@REM 关闭Exploit Protection
PowerShell Set-Processmitigation -System -Disable DEP
PowerShell Set-Processmitigation -System -Disable CFG
PowerShell Set-Processmitigation -System -Disable ForceRelocateImages
PowerShell Set-Processmitigation -System -Disable HighEntropy
PowerShell Set-Processmitigation -System -Disable SEHOP
PowerShell Set-Processmitigation -System -Disable TerminateOnError
@REM 删除Windows Defender菜单项
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
@REM ============


@REM 性能
@REM ============
@REM 启用BBR2
netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2
netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2
@REM 文件系统 - 禁用上次访问时间
fsutil behavior set disableLastAccess 1
@REM 文件系统 - 禁用8.3命名
fsutil behavior set disable8dot3 1
@REM 关闭搜索索引、错误报告、System Guard监控服务
sc stop "wsearch" & sc config "wsearch" start=disabled
sc stop "WerSvc" & sc config "WerSvc" start=disabled
sc stop "SgrmBroker" & sc config "SgrmBroker" start=disabled
@REM 开启传送优化
sc start "DoSvc"
sc config "DoSvc" start=auto
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t REG_DWORD /d 2 /f
@REM 删除旧版QQ安全中心服务
sc delete QPCore
@REM 启用TSX指令集、传送优化
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableTsx /t REG_DWORD /d 0 /f
@REM 关闭MPO
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v OverlayTestMode /t REG_DWORD /d 5 /f
@REM ============


@REM 杂项
@REM ============
@REM 解锁RevisionTool限制
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionSubVersion /t REG_SZ /d "ReviOS" /f
@REM 开启UPNP服务、字体缓存服务
sc config "fdPHost" start=auto
sc config "FDResPub" start=auto
sc config "SSDPSRV" start=auto
sc config "upnphost" start=auto
sc config "SysMain" start=auto
sc config "FontCache3.0.0.0" start=AUTO
sc config "FontCache" start=AUTO
@REM 恢复HPET与动态时钟为默认
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue disabledynamictick
@REM 关闭部分计划任务
SCHTASKS /End /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
SCHTASKS /End /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Wininet\CacheTask" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
@REM 关闭提高鼠标精准度
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
@REM ============


@REM 维护
@REM ============
@REM 重置网络设置
ipconfig /flushdns & netsh int ip reset & netsh winsock reset
echo DISM与SFC需要更长的时间，不需要的话可以关闭窗口了
pause
DISM.exe /Online /Cleanup-image /Restorehealth
sfc /scannow
@REM ============
pause


@REM Get-AppxPackage *windows.immersivecontrolpanel* | Reset-AppxPackage