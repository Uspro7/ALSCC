@echo off
echo 正在设置Go代理...
set GOPROXY=https://goproxy.cn,direct
set GOSUMDB=sum.golang.google.cn

echo 正在下载依赖...
go mod tidy
if %errorlevel% neq 0 (
    echo 依赖下载失败！
    pause
    exit /b 1
)

echo 正在交叉编译为Linux版本...
set GOOS=linux
set GOARCH=amd64
go build -o LinuxSecurityCheck-linux .

if %errorlevel% equ 0 (
    echo 编译成功！生成文件: LinuxSecurityCheck-linux
    echo 请将此文件传输到Linux系统并以root权限运行
) else (
    echo 编译失败！
    pause
    exit /b 1
)

pause