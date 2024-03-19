@echo off
chcp 65001 >nul

@REM 开始获取管理员权限
setlocal
set uac=~uac_permission_tmp_%random%
md "%SystemRoot%\system32\%uac%" 2>nul
if %errorlevel%==0 ( rd "%SystemRoot%\system32\%uac%" >nul ) else (
    echo set uac = CreateObject^("Shell.Application"^)>"%temp%\%uac%.vbs"
    echo uac.ShellExecute "%~s0","","","runas",1 >>"%temp%\%uac%.vbs"
    echo WScript.Quit >>"%temp%\%uac%.vbs"
    "%temp%\%uac%.vbs" /f
    del /f /q "%temp%\%uac%.vbs" & exit )
@REM echo ////////////

chcp 65001 >nul
echo ⚠️ 你需要想办法关闭Windows Denfeder和智能应用控制，才能让部分内容生效🤔
echo=

echo 🛡️ 安全
echo ============
echo 使用最新.NETFramework
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework" /v "OnlyUseLatestCLR" /t REG_DWORD /d 00000001 /f >nul
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" /v "OnlyUseLatestCLR" /t REG_DWORD /d 00000001 /f >nul
echo 关闭内核完整性
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d 0 /f >nul
echo 关闭SystemGuard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "Enabled" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\SgrmAgent" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f >nul
echo 关闭MitigationOptions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d 22222200000200000002000000000000 /f >nul
echo 关闭幽灵熔断、DownFall
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 3 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 33554435 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f >nul
echo 关闭基于虚拟化的安全
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0 /f >nul
bcdedit.exe /set vsmlaunchtype off >nul
bcdedit.exe /set hypervisorlaunchtype off >nul
echo 关闭Exploit Protection
PowerShell Set-Processmitigation -System -Disable DEP >nul
PowerShell Set-Processmitigation -System -Disable CFG >nul
PowerShell Set-Processmitigation -System -Disable ForceRelocateImages >nul
PowerShell Set-Processmitigation -System -Disable HighEntropy >nul
PowerShell Set-Processmitigation -System -Disable SEHOP >nul
PowerShell Set-Processmitigation -System -Disable TerminateOnError >nul
echo 关闭DEP，内核签名和一些校验
bcdedit.exe /set {current} nx AlwaysOff >nul
bcdedit.exe /set {current} pae ForceEnable >nul
bcdedit.exe /set {current} nointegritychecks on >nul
bcdedit.exe /set {current} quietboot on >nul
bcdedit.exe /set {current} bootstatuspolicy IgnoreAllFailures >nul
bcdedit.exe /timeout 0 >nul
echo 关闭Windows Defender部分功能
reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>nul
reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefusersvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>nul
for /f %%i in ('reg query "HKLM\SYSTEM\ControlSet001\Services" /s /k "webthreatdefusersvc" /f 2^>nul ^| find /i "webthreatdefusersvc" ') do (
  reg add "%%i" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>nul
)
reg add "HKLM\SYSTEM\ControlSet001\Services" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >nul
reg add "HKLM\Software\Policies\Microsoft\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\Software\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >nul
echo 删除Windows Defender菜单项
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f >nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f >nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f >nul
echo ////////////
echo=

echo=
echo 🚀 性能
echo ============
@REM 启用BBR2
@REM netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2 >nul 2>nul
@REM netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2 >nul 2>nul
@REM netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2 >nul 2>nul
@REM netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2 >nul 2>nul
@REM netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2 >nul 2>nul
echo 启用TSX指令集
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableTsx /t REG_DWORD /d 0 /f >nul 2>nul
echo 关闭Bitlocker
for %%a in (c d e f g h i j k l m n o p q r s t u v w x y z  ) do (manage-bde.exe -off %%a: >nul 2>nul)
echo 关闭IPv6转换服务
sc stop "iphlpsvc" & sc config "iphlpsvc" start=disabled >nul  2>nul
echo 关闭MPO
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v OverlayTestMode /t REG_DWORD /d 5 /f >nul 2>nul
echo 关闭程序兼容性助手
sc stop "PcaSvc" & sc config "PcaSvc" start=disabled >nul 2>nul
echo 关闭错误报告
sc stop "WerSvc" & sc config "WerSvc" start=disabled >nul 2>nul
echo 关闭使用情况报告
wevtutil sl Microsoft-Windows-SleepStudy/Diagnostic /q:false
wevtutil sl Microsoft-Windows-Kernel-Processor-Power/Diagnostic /q:false
wevtutil sl Microsoft-Windows-UserModePowerService/Diagnostic /q:false
reg add "HKLM\SYSTEM\ControlSet001\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >nul 2>nul
reg add "HKLM\SYSTEM\ControlSet001\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >nul 2>nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >nul 2>nul
echo 关闭搜索索引
sc stop "wsearch" & sc config "wsearch" start=disabled >nul 2>nul
echo 文件系统 - 禁用8.3命名
fsutil behavior set disable8dot3 1 >nul 2>nul
echo 文件系统 - 禁用上次访问时间
fsutil behavior set disableLastAccess 1 >nul 2>nul
echo ////////////
echo=

echo=
echo ⚙️ 杂项
echo ============
echo 解锁RevisionTool限制
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionSubVersion /t REG_SZ /d "ReviOS" /f >nul 2>nul
echo 恢复HPET与动态时钟为默认
bcdedit /deletevalue useplatformclock >nul 2>nul
bcdedit /deletevalue disabledynamictick >nul 2>nul
echo 关闭提高鼠标精准度
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f >nul 2>nul
echo 删除旧版QQ安全中心服务
sc delete QPCore >nul
echo 删除右键菜单 - 兼容性疑难解答
reg delete "HKCR\exefile\shellex\ContextMenuHandlers\Compatibility" /f >nul 2>nul
echo 删除右键菜单 - 共享
reg delete "HKCR\*\shellex\ContextMenuHandlers\Sharing" /f >nul 2>nul
echo 删除右键菜单 - 包含到库中
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location" /f >nul 2>nul
echo 删除右键菜单 - 添加到收藏夹
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\FavMenu" /f >nul 2>nul
reg add "HKCR\*\shell\pintohomefile" /v "LegacyDisable" /f >nul 2>nul
reg add "HKCR\*\shell\pintohomefile" /v "ProgrammaticAccessOnly" /f >nul 2>nul
reg add "HKCR\*\shell\pintohomefile" /v "HideBasedOnVelocityId" /t REG_DWORD /d 6527944 /f >nul 2>nul
echo 删除右键菜单 - 授予访问权限
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6}" /t REG_SZ /d 0 /f >nul 2>nul
echo 删除右键菜单 - 上传到百度网盘
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
reg delete "HKCR\*\shellex\-ContextMenuHandlers\YunShellExt" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
echo ////////////
echo=

echo=
echo 🛠️ 维护
echo ============
echo 重置网络设置
ipconfig /flushdns >nul 2>nul
netsh int ip reset >nul 2>nul
netsh winsock reset >nul 2>nul
echo 关闭IPv6
netsh interface ipv6 set teredo disabled >nul 2>nul
netsh interface ipv6 set privacy disabled >nul 2>nul
echo ////////////
echo=

echo=
echo 🪟 系统修复
echo ============
echo ⚠️ DISM和SFC需要网络连接以及很长的时间，不需要的话可以关闭窗口了😎
echo 按任意键开始
pause
DISM.exe /Online /Cleanup-image /Restorehealth
sfc /scannow
echo ////////////
pause


@REM Get-AppxPackage *windows.immersivecontrolpanel* | Reset-AppxPackage