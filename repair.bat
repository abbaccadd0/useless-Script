@echo off
chcp 65001 >nul

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
@REM echo ////////////

chcp 65001 >nul
echo ⚠️ 你需要想办法关闭Windows Denfeder和智能应用控制，才能让部分内容生效🤔
echo=

echo 🛡️ 安全
echo ============
echo 使用最新.NETFramework
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework" /v "OnlyUseLatestCLR" /t REG_DWORD /d 00000001 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" /v "OnlyUseLatestCLR" /t REG_DWORD /d 00000001 /f >nul
echo 关闭内核完整性
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d 0 /f >nul
echo 关闭SystemGuard
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "Enabled" /t REG_DWORD /d 0 /f >nul
echo 关闭MitigationOptions
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d 22222200000200000002000000000000 /f >nul
echo 关闭幽灵、熔断、DownFall
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 33554435 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f >nul
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
@REM netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2 >nul
@REM netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2 >nul
@REM netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2 >nul
@REM netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2 >nul
@REM netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2 >nul
echo 文件系统 - 禁用上次访问时间
fsutil behavior set disableLastAccess 1 >nul
echo 文件系统 - 禁用8.3命名
fsutil behavior set disable8dot3 1 >nul
echo 关闭搜索索引
sc stop "wsearch" & sc config "wsearch" start=disabled >nul
echo 关闭错误报告
sc stop "WerSvc" & sc config "WerSvc" start=disabled >nul
echo 关闭System Guard监控
sc stop "SgrmBroker" & sc config "SgrmBroker" start=disabled >nul
echo 关闭程序兼容性助手
sc stop "PcaSvc" & sc config "PcaSvc" start=disabled >nul
echo 关闭IPv6转换服务
sc stop "iphlpsvc" & sc config "iphlpsvc" start=disabled >nul
echo 启用TSX指令集
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableTsx /t REG_DWORD /d 0 /f >nul
echo 关闭MPO
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v OverlayTestMode /t REG_DWORD /d 5 /f >nul
echo 删除旧版QQ安全中心服务
sc delete QPCore >nul
echo ////////////
echo=

echo=
echo ⚙️ 杂项
echo ============
echo 解锁RevisionTool限制
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionSubVersion /t REG_SZ /d "ReviOS" /f >nul
echo 恢复HPET与动态时钟为默认
bcdedit /deletevalue useplatformclock >nul
bcdedit /deletevalue disabledynamictick >nul
echo 关闭提高鼠标精准度
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f >nul
echo 删除右键菜单 - 兼容性疑难解答
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\Compatibility" /f >nul
echo 删除右键菜单 - 共享
reg delete "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing" /f >nul
echo 删除右键菜单 - 包含到库中
reg delete "HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\Library Location" /f >nul
echo 删除右键菜单 - 添加到收藏夹
reg delete "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\FavMenu" /f >nul
echo 删除右键菜单 - 授予访问权限
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6}" /t REG_SZ /d 0 /f >nul
echo ////////////
echo=

echo=
echo 🛠️ 维护
echo ============
echo 重置网络设置
ipconfig /flushdns >nul & netsh int ip reset >nul & netsh winsock reset >nul
echo 关闭IPv6
netsh interface ipv6 set teredo disabled >nul
netsh interface ipv6 set privacy disabled >nul
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