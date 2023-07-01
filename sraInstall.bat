@echo off

chcp 65001
setlocal
set uac=~uac_permission_tmp_%random%
md "%SystemRoot%\system32\%uac%" 2>nul
if %errorlevel%==0 ( rd "%SystemRoot%\system32\%uac%" >nul 2>nul ) else (
    echo set uac = CreateObject^("Shell.Application"^)>"%temp%\%uac%.vbs"
    echo uac.ShellExecute "%~s0","","","runas",1 >>"%temp%\%uac%.vbs"
    echo WScript.Quit >>"%temp%\%uac%.vbs"
    "%temp%\%uac%.vbs" /f
    del /f /q "%temp%\%uac%.vbs" & exit )
endlocal

:start
echo 星穹铁道小助手便捷安装程式
echo 本人不为StarRailAssistant背书，反之亦然。请谨记米哈游的协议，搞清楚自己在干什么。
echo ==================
echo. 
echo 是否需要透过winget安装Python和Git?
echo. 
echo (y)需要安装 (s)静默安装 (n)不安装 (其他按键)终止批处理
echo. 
set /p mode=请输入并按下回车: || set "mode=0"
if "%mode%"=="y" (
    echo 正在透过winget安装Python和Git，请注意弹出来的安装窗口
    winget install -e -i --id=Python.Python.3.11 --source=winget --scope=machine && winget install -e -i --id=Git.Git --source=winget --scope=machine && goto clone
) else (
    if "%mode%"=="s" (
        echo 正在透过winget静默安装Python和Git，它们将被安装至默认位置，请坐和放宽
        winget install -e -h --id=Python.Python.3.11 --source=winget --scope=machine && winget install -e -h --id=Git.Git --source=winget --scope=machine && goto clone
    ) else (
        if "%mode%"=="n" (
            echo 将不会进行安装，请确定你具备要求的环境
            goto clone
        ) else (
            echo 已终止程式
            pause
            exit
        )
    )
)

:clone
cd /d %~dp0
set tmp=python %~dp0StarRailAssistant\Honkai_Star_Rail.py
git clone https://github.com/Starry-Wind/StarRailAssistant
cd StarRailAssistant
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
pip config set global.extra-index-url "https://mirrors.aliyun.com/pypi/simple/ https://pypi.org/simple/"
python -m pip install --upgrade pip
pip install -r requirements.txt
echo 安装完成，正在创建快捷方式
cd ..
del /F /Q 启动StarRailAssistant.bat >nul 2>nul
cd. > 启动StarRailAssistant.bat
echo @echo off > 启动StarRailAssistant.bat
echo echo StarRailAssistant正在启动，该窗口将会关闭，并拉起Python >> 启动StarRailAssistant.bat
echo timeout /t 5 /nobreak ^> nul >> 启动StarRailAssistant.bat
echo %%1 mshta vbscript:CreateObject("WScript.Shell").Run("%%~s0 ::",0,FALSE)(window.close)^&^&exit >> 启动StarRailAssistant.bat
echo cd /d %~dp0StarRailAssistant\ >> 启动StarRailAssistant.bat
echo %tmp% >> 启动StarRailAssistant.bat
echo 创建完成
pause
exit