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
endlocal

:start
echo �������С���ֱ�ݰ�װ��ʽ
echo ���˲�ΪStarRailAssistant���飬��֮��Ȼ��������׹��ε�Э�飬������Լ��ڸ�ʲô��
echo ==================
echo. 
echo �Ƿ���Ҫ͸��winget��װPython��Git?
echo. 
echo (y)��Ҫ��װ (s)��Ĭ��װ (n)����װ (��������)��ֹ������
echo. 
set /p mode=�����벢���»س�: || set "mode=0"
if "%mode%"=="y" (
    echo ����͸��winget��װPython��Git����ע�ⵯ�����İ�װ����
    winget install -e -i --id=Python.Python.3.11 --source=winget --scope=machine && winget install -e -i --id=Git.Git --source=winget --scope=machine && goto clone
) else (
    if "%mode%"=="s" (
        echo ����͸��winget��Ĭ��װPython��Git�����ǽ�����װ��Ĭ��λ�ã������ͷſ�
        winget install -e -h --id=Python.Python.3.11 --source=winget --scope=machine && winget install -e -h --id=Git.Git --source=winget --scope=machine && goto clone
    ) else (
        if "%mode%"=="n" (
            echo ��������а�װ����ȷ����߱�Ҫ��Ļ���
            goto clone
        ) else (
            echo ����ֹ��ʽ
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
echo ��װ��ɣ����ڴ�����ݷ�ʽ
cd ..
del /F /Q ����StarRailAssistant.bat >nul 2>nul
cd. > ����StarRailAssistant.bat
echo @echo off > ����StarRailAssistant.bat
echo echo StarRailAssistant�����������ô��ڽ���رգ�������Python >> ����StarRailAssistant.bat
echo timeout /t 5 /nobreak ^> nul >> ����StarRailAssistant.bat
echo %%1 mshta vbscript:CreateObject("WScript.Shell").Run("%%~s0 ::",0,FALSE)(window.close)^&^&exit >> ����StarRailAssistant.bat
echo cd /d %~dp0StarRailAssistant\ >> ����StarRailAssistant.bat
echo %tmp% >> ����StarRailAssistant.bat
echo �������
pause
exit