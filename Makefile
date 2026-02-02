# LinuxSecurityCheck Makefile

.PHONY: build clean install run test

# 程序名称
BINARY_NAME=LinuxSecurityCheck

# LinuxSecurityCheck Makefile

.PHONY: build clean install test help

# 程序名称
BINARY_NAME=LinuxSecurityCheck

# 交叉编译为Linux可执行文件（默认构建目标）
build:
	powershell -Command "$$env:GOOS='linux'; $$env:GOARCH='amd64'; go build -o $(BINARY_NAME)-linux ."

# Windows下构建（仅用于测试编译）
build-windows:
	go build -o $(BINARY_NAME).exe .

# 清理构建文件
clean:
	powershell -Command "Remove-Item -Force $(BINARY_NAME)-linux, $(BINARY_NAME).exe -ErrorAction SilentlyContinue"

# 安装依赖
install:
	powershell -Command "$$env:GOPROXY='https://goproxy.cn,direct'; $$env:GOSUMDB='sum.golang.google.cn'; go mod tidy"

# 测试编译（Linux版本）
test:
	powershell -Command "$$env:GOOS='linux'; $$env:GOARCH='amd64'; go build -o $(BINARY_NAME)-linux ."
	@echo "Linux版本编译成功！"

# 测试编译（Windows版本，仅用于语法检查）
test-windows:
	go build -o $(BINARY_NAME).exe .
	@echo "Windows版本编译成功（仅用于测试）！"

# 显示帮助
help:
	@echo "可用的make命令:"
	@echo "  build        - 交叉编译为Linux可执行文件"
	@echo "  build-windows- 编译Windows版本（仅用于测试）"
	@echo "  clean        - 清理构建文件"
	@echo "  install      - 安装依赖"
	@echo "  test         - 测试编译Linux版本"
	@echo "  test-windows - 测试编译Windows版本"
	@echo "  help         - 显示此帮助信息"