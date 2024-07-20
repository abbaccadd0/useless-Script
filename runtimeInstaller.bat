@echo off

setlocal
set uac=~uac_permission_tmp_%random%
md "%SystemRoot%\system32\%uac%" 2>nul
if %errorlevel%==0 ( rd "%SystemRoot%\system32\%uac%" >nul 2>nul ) else (
    echo set uac = CreateObject^("Shell.Application"^)>"%temp%\%uac%.vbs"
    echo uac.ShellExecute "%~s0","","","runas",1 >>"%temp%\%uac%.vbs"
    echo WScript.Quit >>"%temp%\%uac%.vbs"
    "%temp%\%uac%.vbs" /f
    del /f /q "%temp%\%uac%.vbs" & exit )

winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.EdgeWebView2Runtime
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2005.x86
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2005.x64
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2008.x86
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2008.x64
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2010.x86
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2010.x64
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2012.x86
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2012.x64
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2013.x86
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2013.x64
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2015+.x86
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.VCRedist.2015+.x64
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.DotNet.DesktopRuntime.6 -a x86 --uninstall-previous
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.DotNet.DesktopRuntime.6 -a x64 --uninstall-previous
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.DotNet.DesktopRuntime.7
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.DotNet.DesktopRuntime.8
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.DotNet.DesktopRuntime.Preview
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.XNARedist
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id Microsoft.DirectX
echo.
winget install --accept-source-agreements --accept-package-agreements --force -h --id OpenAL.OpenAL
echo.
pause