@echo off
chcp 65001 >nul

@REM 获取管理员权限
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
echo ⚠️ 部分内容需要你想办法关闭Windows Denfeder和智能应用控制才能生效🤔
echo=

echo 🛡️ 安全
echo ============
echo 使用最新.NETFramework
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework" /v "OnlyUseLatestCLR" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" /v "OnlyUseLatestCLR" /t REG_DWORD /d "1" /f >nul
echo 关闭基于虚拟化的安全
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "0" /f >nul 2>nul
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VBS
bcdedit /set vsmlaunchtype off >nul
bcdedit /set hypervisorlaunchtype off >nul
echo 关闭内核完整性
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f >nul
echo 关闭幽灵熔断、DownFall
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "33554435" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul
echo 关闭MitigationOptions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "22222200000200000002000000000000" /f >nul
echo 关闭SystemGuard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "Enabled" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\SgrmAgent" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f >nul
echo 关闭Exploit Protection
PowerShell Set-Processmitigation -System -Disable DEP >nul
PowerShell Set-Processmitigation -System -Disable CFG >nul
PowerShell Set-Processmitigation -System -Disable ForceRelocateImages >nul
PowerShell Set-Processmitigation -System -Disable HighEntropy >nul
PowerShell Set-Processmitigation -System -Disable SEHOP >nul
PowerShell Set-Processmitigation -System -Disable TerminateOnError >nul
echo 关闭DEP、内核签名等
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
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f >nul
reg add HKLM\System\ControlSet001\Services\MDCoreSvc /v Start /t REG_DWORD /d 4 /f >nul
echo 删除Windows Defender菜单项
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f >nul 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f >nul 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f >nul 2>nul
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
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "0" /f >nul 2>nul
echo 启用内存压缩
PowerShell Enable-MMAgent -mc
echo 关闭ACPI C2和C3
reg add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Capabilities" /t REG_DWORD /d "0x0007e066" /f >nul 2>nul
echo 关闭Bitlocker
for %%a in (c d e f g h i j k l m n o p q r s t u v w x y z  ) do (manage-bde.exe -off %%a: >nul 2>nul)
echo 关闭IPv6转换服务
sc start "iphlpsvc" >nul 2>nul
sc config "iphlpsvc" start=disabled >nul  2>nul
@REM echo 启用MPO
@REM reg delete "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode"  /f >nul 2>nul
echo 关闭MPO
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f >nul 2>nul
echo 关闭程序兼容性助手
sc stop "PcaSvc" >nul 2>nul
sc config "PcaSvc" start=disabled >nul 2>nul
echo 关闭错误报告
sc stop "WerSvc" >nul 2>nul
sc config "WerSvc" start=disabled >nul 2>nul
echo 关闭使用情况报告
wevtutil sl Microsoft-Windows-SleepStudy/Diagnostic /q:false
wevtutil sl Microsoft-Windows-Kernel-Processor-Power/Diagnostic /q:false
wevtutil sl Microsoft-Windows-UserModePowerService/Diagnostic /q:false
reg add "HKLM\SYSTEM\ControlSet001\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>nul
reg add "HKLM\SYSTEM\ControlSet001\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>nul
reg add "HKLM\SYSTEM\ControlSet001\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>nul
echo 关闭搜索索引
sc stop "wsearch" >nul 2>nul
sc config "wsearch" start=disabled >nul 2>nul
echo 文件系统 - 禁用8.3命名
fsutil behavior set disable8dot3 1 >nul 2>nul
echo 文件系统 - 禁用上次访问时间
fsutil behavior set disableLastAccess 1 >nul 2>nul
echo 增加NTFS分页池内存限制
fsutil behavior set memoryusage 2 >nul 2>nul
echo ////////////
echo=

echo=
echo ⚙️ 杂项
echo ============
echo 关闭iTunes自动备份
iTunes.exe /setPrefInt DeviceBackupsDisabled 1
echo 关闭提高鼠标精准度
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul 2>nul
echo 恢复HPET与动态时钟为默认
bcdedit /deletevalue useplatformclock >nul 2>nul
bcdedit /deletevalue disabledynamictick >nul 2>nul
echo 减少关机程序等待时间
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul 2>nul
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1600" /f >nul 2>nul
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1600" /f >nul 2>nul
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1600" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1600" /f >nul 2>nul
echo 解锁RevisionTool限制
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v "EditionSubVersion" /t REG_SZ /d "ReviOS" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Revision-ReviOS" /v "EditionSubVersion" /t REG_SZ /d "ReviOS" /f >nul 2>nul
echo 开启蓝屏自动重启
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d "1" /f >nul 2>nul
echo 删除旧版QQ安全中心服务
sc delete QPCore >nul 2>nul
echo 删除快捷方式字样
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f >nul 2>nul
echo 提高图标缓存
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "8192" /f >nul 2>nul
echo 删除右键菜单 - Bitlocker
reg delete "HKCR\Drive\shell\change-passphrase" /f >nul 2>nul
reg delete "HKCR\Drive\shell\change-pin" /f >nul 2>nul
reg delete "HKCR\Drive\shell\encrypt-bde" /f >nul 2>nul
reg delete "HKCR\Drive\shell\encrypt-bde-elev" /f >nul 2>nul
reg delete "HKCR\Drive\shell\manage-bde" /f >nul 2>nul
reg delete "HKCR\Drive\shell\resume-bde" /f >nul 2>nul
reg delete "HKCR\Drive\shell\resume-bde-elev" /f >nul 2>nul
@REM reg delete "HKCR\Drive\shell\unlock-bde" /f >nul 2>nul
echo 删除右键菜单 - 包含到库中
reg delete "HKCR\*\shellex\ContextMenuHandlers\Library Location" /f >nul 2>nul
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Library Location" /f >nul 2>nul
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\Library Location" /f >nul 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\Library Location" /f >nul 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\Library Location" /f >nul 2>nul
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\Library Location" /f >nul 2>nul
echo 删除右键菜单 - 工作文件夹
reg delete "HKCR\*\shellex\ContextMenuHandlers\WorkFolders" /f >nul 2>nul
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\WorkFolders" /f >nul 2>nul
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\WorkFolders" /f >nul 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\WorkFolders" /f >nul 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\WorkFolders" /f >nul 2>nul
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\WorkFolders" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\WorkFolders" /f >nul 2>nul
echo 删除右键菜单 - 共享
reg delete "HKCR\*\shellex\ContextMenuHandlers\Sharing" /f >nul 2>nul
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Sharing" /f >nul 2>nul
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\Sharing" /f >nul 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\Sharing" /f >nul 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\Sharing" /f >nul 2>nul
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\Sharing" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\Sharing" /f >nul 2>nul
echo 删除右键菜单 - 还原以前的版本
reg delete "HKCR\*\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>nul
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>nul
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>nul
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>nul
echo 删除右键菜单 - 加密
reg delete "HKCR\*\shellex\ContextMenuHandlers\Open With EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Open With EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\Open With EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\Open With EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\Open With EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\Open With EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\Open With EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\*\shellex\ContextMenuHandlers\EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\EncryptionMenu" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\EncryptionMenu" /f >nul 2>nul
echo 删除右键菜单 - 兼容性疑难解答
reg delete "HKCR\exefile\shellex\ContextMenuHandlers\Compatibility" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\Compatibility" /f >nul 2>nul
echo 删除右键菜单 - 上传到百度网盘
reg delete "HKCR\*\shellex\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
reg delete "HKCR\lnkfile\shellex\ContextMenuHandlers\YunShellExt" /f >nul 2>nul
echo 删除右键菜单 - 授予访问权限
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6}" /t REG_SZ /d "0" /f >nul 2>nul
echo 删除右键菜单 - 添加到收藏夹
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\FavMenu" /f >nul 2>nul
reg add "HKCR\*\shell\pintohomefile" /v "LegacyDisable" /f >nul 2>nul
reg add "HKCR\*\shell\pintohomefile" /v "ProgrammaticAccessOnly" /f >nul 2>nul
reg add "HKCR\*\shell\pintohomefile" /v "HideBasedOnVelocityId" /t REG_DWORD /d "6527944" /f >nul 2>nul
echo ////////////
echo=

echo=
echo 🛠️ 维护
echo ============
echo 关闭IPv6
netsh interface ipv6 set teredo disabled >nul 2>nul
netsh interface ipv6 set privacy disabled >nul 2>nul
PowerShell Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 >nul 2>nul
echo 重置网络设置
ipconfig /flushdns >nul 2>nul
netsh int ip reset >nul 2>nul
netsh winsock reset >nul 2>nul
echo 重置文件默认夹视图
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\FavMenu" /v "FolderType" /f >nul 2>nul
echo 清理Edge缓存
taskkill /F /IM "msedge.exe" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Code Cache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\DawnCache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\DawnGraphiteCache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\DawnWebGPUCache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\GPUCache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\optimization_guide_hint_cache_store" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Shared Dictionary\cache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Service Worker\ScriptCache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\GraphiteDawnCache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\GrShaderCache" >nul 2>nul
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\ShaderCache" >nul 2>nul
echo 伪造MDM-Enrollment
reg add "HKLM\SOFTWARE\Microsoft\Enrollments\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" /v "EnrollmentState" /t REG_DWORD /d "1" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Enrollments\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" /v "EnrollmentType" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Enrollments\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" /v "IsFederated" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" /v "Flags" /t REG_DWORD /d "00d6fb7f" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" /v "AcctUId" /t REG_SZ /d "0x000000000000000000000000000000000000000000000000000000000000000000000000" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" /v "RoamingCount" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" /v "SslClientCertReference" /t REG_SZ /d "MY;User;0000000000000000000000000000000000000000" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" /v "ProtoVer" /t REG_SZ /d "1.2" /f >nul 2>nul
echo 增加单进程可用内存量
bcdedit /set increaseuserva 8192 >nul 2>nul
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