# LinuxSecurityCheck 构建脚本
# PowerShell 脚本用于在Windows下交叉编译Linux版本

Write-Host "正在设置Go代理..." -ForegroundColor Green
$env:GOPROXY = "https://goproxy.cn,direct"
$env:GOSUMDB = "sum.golang.google.cn"

Write-Host "正在下载依赖..." -ForegroundColor Green
go mod tidy

if ($LASTEXITCODE -ne 0) {
    Write-Host "依赖下载失败！" -ForegroundColor Red
    exit 1
}

Write-Host "正在交叉编译为Linux版本..." -ForegroundColor Green
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o LinuxSecurityCheck-linux .

if ($LASTEXITCODE -eq 0) {
    Write-Host "编译成功！生成文件: LinuxSecurityCheck-linux" -ForegroundColor Green
    Write-Host "请将此文件传输到Linux系统并以root权限运行" -ForegroundColor Yellow
} else {
    Write-Host "编译失败！" -ForegroundColor Red
    exit 1
}