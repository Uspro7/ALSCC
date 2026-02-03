package main

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type screen int

const (
	mainMenu screen = iota
	userList
	passwordExpiry
	passwordChange
	passwordTypeSelect
	passwordInput
	lockPolicyCheck
	lockPolicyInput
	emergencyUnlock
	lockPolicyOptions
	securityCheck
	securityCheckResults
	weakPasswordCheck
	weakPasswordResults
	weakPasswordConfig
	weakPasswordDictInput
)

type passwordType int

const (
	uniformPassword passwordType = iota
	ruleBasedPassword
	randomPassword
)

type User struct {
	Username    string
	UID         int
	Shell       string
	LastChanged time.Time
	DaysUsed    int
	Selected    bool
}

type model struct {
	currentScreen      screen
	cursor            int
	users             []User
	selectedUsers     []User
	passwordType      passwordType
	uniformPass       string
	rulePrefix        string
	inputValue        string
	inputPrompt       string
	inputMode         bool
	message           string
	showPassword      bool
	generatedPasswords map[string]string
	// 锁定策略相关
	currentLockAttempts int
	currentLockTime     int
	newLockAttempts     int
	newLockTime         int
	lockPolicyFiles     []string
	lockInputType       string // "attempts" 或 "time"
	rootWhitelist       bool   // root白名单选项
	emergencyMode       bool   // 紧急模式
	// 安全检查相关
	strictMode          bool   // 严格模式（只检查不修改）
	securityResults     []SecurityCheckResult
	selectedChecks      []bool // 选中的检查项
	// 弱口令检测相关
	weakPasswordResults  []WeakPasswordResult
	weakPasswordConfig   PerformanceConfig
	dictionaryFilePath   string // 当前选择的字典文件路径
	availableDictionaries []string // 可用的字典文件列表
	// Root用户检测开关（全局控制）
	enableRootCheck      bool // 是否启用Root用户检测/修改
	// 进度条相关
	progressCurrent     int    // 当前进度
	progressTotal       int    // 总进度
	progressMessage     string // 进度消息
	showProgress        bool   // 是否显示进度条
	isProcessing        bool   // 是否正在处理中
}

// 进度更新消息
type progressMsg struct {
	current int
	total   int
	message string
}

// 完成消息
type completeMsg struct {
	results interface{}
	err     error
}

// 步骤执行消息
type stepMsg struct {
	stepIndex int
	totalSteps int
	stepName string
	results []SecurityCheckResult
	selectedItems []int
	strictMode bool
}

// 弱口令检测步骤消息
type weakPasswordStepMsg struct {
	stepIndex int
	totalSteps int
	usernames []string
	hashes map[string]string
	passwords []string
	config PerformanceConfig
	results []WeakPasswordResult
}

func initialModel() model {
	users, err := getSystemUsers()
	if err != nil {
		return model{
			message: fmt.Sprintf("获取用户列表失败: %v", err),
		}
	}

	// 扫描可用的字典文件
	dictFiles, _ := scanAvailableDictionaries()
	defaultDict := "Top1000pass.txt"

	// 如果默认字典不存在，使用第一个找到的字典
	if len(dictFiles) > 0 {
		// 检查默认字典是否存在
		found := false
		for _, f := range dictFiles {
			if f == defaultDict {
				found = true
				break
			}
		}
		if !found && len(dictFiles) > 0 {
			defaultDict = dictFiles[0]
		}
	}

	return model{
		currentScreen:         mainMenu,
		users:                users,
		generatedPasswords:   make(map[string]string),
		dictionaryFilePath:   defaultDict,
		availableDictionaries: dictFiles,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case progressMsg:
		// 更新进度条
		m.progressCurrent = msg.current
		m.progressTotal = msg.total
		m.progressMessage = msg.message
		return m, nil
	case stepMsg:
		// 处理安全检查步骤执行
		if msg.stepIndex >= len(msg.selectedItems) {
			// 所有步骤完成
			m.showProgress = false
			m.isProcessing = false
			m.securityResults = msg.results
			m.message = "安全检查完成"
			return m, nil
		}
		
		// 更新进度
		m.progressCurrent = msg.stepIndex + 1
		m.progressTotal = msg.totalSteps
		checkIndex := msg.selectedItems[msg.stepIndex]
		m.progressMessage = fmt.Sprintf("正在检查: %s", SecurityChecks[checkIndex].Name)
		
		// 执行当前步骤并返回下一步命令
		return m, executeSecurityCheckStep(msg)
	case weakPasswordStepMsg:
		// 处理弱口令检测步骤执行
		if msg.stepIndex >= len(msg.usernames) {
			// 所有步骤完成
			m.showProgress = false
			m.isProcessing = false
			m.weakPasswordResults = msg.results
			m.message = "弱口令检测完成"
			return m, nil
		}
		
		// 更新进度
		m.progressCurrent = msg.stepIndex + 1
		m.progressTotal = msg.totalSteps
		username := msg.usernames[msg.stepIndex]
		m.progressMessage = fmt.Sprintf("正在检测用户: %s", username)
		
		// 执行当前步骤并返回下一步命令
		return m, executeWeakPasswordCheckStep(msg)
	case completeMsg:
		// 处理完成
		m.showProgress = false
		m.isProcessing = false
		if msg.err != nil {
			m.message = fmt.Sprintf("操作失败: %v", msg.err)
		} else {
			// 根据结果类型更新相应的数据
			switch results := msg.results.(type) {
			case []SecurityCheckResult:
				m.securityResults = results
				m.message = "安全检查完成"
			case []WeakPasswordResult:
				m.weakPasswordResults = results
				m.message = "弱口令检测完成"
			}
		}
		return m, nil
	case tea.KeyMsg:
		// 如果正在处理中，只允许退出
		if m.isProcessing {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			}
			return m, nil
		}
		
		switch m.currentScreen {
		case mainMenu:
			return m.updateMainMenu(msg)
		case userList:
			return m.updateUserList(msg)
		case passwordExpiry:
			return m.updatePasswordExpiry(msg)
		case passwordChange:
			return m.updatePasswordChange(msg)
		case passwordTypeSelect:
			return m.updatePasswordTypeSelect(msg)
		case passwordInput:
			return m.updatePasswordInput(msg)
		case lockPolicyCheck:
			return m.updateLockPolicyCheck(msg)
		case lockPolicyInput:
			return m.updateLockPolicyInput(msg)
		case emergencyUnlock:
			return m.updateEmergencyUnlock(msg)
		case lockPolicyOptions:
			return m.updateLockPolicyOptions(msg)
		case securityCheck:
			return m.updateSecurityCheck(msg)
		case securityCheckResults:
			return m.updateSecurityCheckResults(msg)
		case weakPasswordCheck:
			return m.updateWeakPasswordCheck(msg)
		case weakPasswordResults:
			return m.updateWeakPasswordResults(msg)
		case weakPasswordConfig:
			return m.updateWeakPasswordConfig(msg)
		case weakPasswordDictInput:
			return m.updateWeakPasswordDictInput(msg)
		}
	case time.Time:
		// 处理定时器消息，用于更新动画
		if m.showProgress && m.isProcessing {
			return m, tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
				return t
			})
		}
	}
	return m, nil
}

func (m model) View() string {
	switch m.currentScreen {
	case mainMenu:
		return m.viewMainMenu()
	case userList:
		return m.viewUserList()
	case passwordExpiry:
		return m.viewPasswordExpiry()
	case passwordChange:
		return m.viewPasswordChange()
	case passwordTypeSelect:
		return m.viewPasswordTypeSelect()
	case passwordInput:
		return m.viewPasswordInput()
	case lockPolicyCheck:
		return m.viewLockPolicyCheck()
	case lockPolicyInput:
		return m.viewLockPolicyInput()
	case emergencyUnlock:
		return m.viewEmergencyUnlock()
	case lockPolicyOptions:
		return m.viewLockPolicyOptions()
	case securityCheck:
		return m.viewSecurityCheck()
	case securityCheckResults:
		return m.viewSecurityCheckResults()
	case weakPasswordCheck:
		return m.viewWeakPasswordCheck()
	case weakPasswordResults:
		return m.viewWeakPasswordResults()
	case weakPasswordConfig:
		return m.viewWeakPasswordConfig()
	case weakPasswordDictInput:
		return m.viewWeakPasswordDictInput()
	}
	return ""
}

// 样式定义 - 丰富的彩色界面
var (
	// 主标题样式 - 紫色渐变背景
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#8B5CF6")).
		Padding(0, 2).
		MarginBottom(1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#A855F7"))

	// 选中项样式 - 亮青色
	selectedStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FFFF")).
		Background(lipgloss.Color("#1E293B")).
		Padding(0, 1)

	// 普通文本样式 - 白色
	normalStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F8FAFC"))

	// 警告样式 - 橙色
	warningStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#F59E0B")).
		Background(lipgloss.Color("#451A03")).
		Padding(0, 1)

	// 危险样式 - 红色
	dangerStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#EF4444")).
		Background(lipgloss.Color("#450A0A")).
		Padding(0, 1)

	// 成功样式 - 绿色
	successStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#10B981")).
		Background(lipgloss.Color("#064E3B")).
		Padding(0, 1)

	// 帮助文本样式 - 灰色
	helpStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94A3B8")).
		Italic(true)

	// 高亮样式 - 黄色背景
	highlightStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#1F2937")).
		Background(lipgloss.Color("#FDE047")).
		Padding(0, 1)

	// 信息样式 - 蓝色
	infoStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#3B82F6")).
		Background(lipgloss.Color("#1E3A8A")).
		Padding(0, 1)

	// 边框样式
	borderStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#6366F1")).
		Padding(1, 2)

	// 面板样式
	panelStyle = lipgloss.NewStyle().
		Background(lipgloss.Color("#0F172A")).
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("#7C3AED")).
		Padding(1, 2).
		MarginBottom(1)
)
// 安全检查结果
type SecurityCheckResult struct {
	ID          int
	Name        string
	Description string
	Level       string // 高、中、低、极高
	Status      string // 合规、不合规、检查失败
	Details     string
	Command     string
	FixSuggestion string
	RawOutput     string // 原始命令输出
	Category      string // 类别：工具、账号、口令、认证、权限、日志、网络、服务、配置、合规、资源
}

// 安全检查项定义 - 整合所有检查项目
var SecurityChecks = []SecurityCheckResult{
	// 工具类检查 (1-2)
	{ID: 1, Name: "网络嗅探类工具检查", Description: "检查系统是否存在tcpdump、wireshark等网络嗅探工具", Level: "中", Category: "工具", Command: `rpm -qa |egrep "\btcpdump\b|\bwireshark\b|\bethereal\b"`},
	{ID: 2, Name: "开发编译类工具检查", Description: "检查系统是否存在gcc、gdb、strace等开发编译工具", Level: "中", Category: "工具", Command: `rpm -qa |egrep "\btcpdump\b|\bgdb\b|\bstrace\b|\bdexdump\b|^\bcpp\b|\bgcc\b|\bwireshark\b|\bethereal\b|\bgcc3\b|\bgcc3-c++\b|\b gcc3-g77\b|\bgcc3-java\b|\bgcc3-objc\b|\bgcc-c++\b|\bgcc-chill\b|\bgcc-g77\b|\bgcc-java\b|\bgcc-objc\b|\bbin86\b|\bdev86\b|\bnasm\b"`},
	
	// 账号类检查 (3-6)
	{ID: 3, Name: "非root且UID为0的用户检查", Description: "检查是否存在除root外UID为0的用户账号", Level: "高", Category: "账号", Command: `awk -F: '($3==0)' /etc/passwd`},
	{ID: 4, Name: "共用账号检查", Description: "检查是否存在多人共用的账号", Level: "中", Category: "账号", Command: `cat /etc/passwd | awk -F: '{print $1}' | sort | uniq -d`},
	{ID: 5, Name: "无关账号检查", Description: "检查是否删除或锁定无关账号", Level: "高", Category: "账号", Command: `cat /etc/shadow |egrep -w "^nfsnobody|^listen|^gdm|^webservd|^nobody4|^noaccess|^adm|^apache|^at|^avahi|^bin|^daemon|^dbus|^distcache|^ftp|^gopher|^haldaemon|^irc|^ldap|^mail|^wwwrun|^webalizer|^vcsa"`},
	{ID: 6, Name: "用户组权限限制检查", Description: "检查业务账户是否归属于独立的GID", Level: "低", Category: "账号", Command: `cat /etc/group | awk -F: '{print $3}' | sort | uniq -d`},
	
	// 口令类检查 (7-12)
	{ID: 7, Name: "口令生存周期检查", Description: "检查口令生存周期要求", Level: "高", Category: "口令", Command: `cat /etc/login.defs |sed '/^#/d'|sed '/^$/d'`},
	{ID: 8, Name: "口令更改最小间隔检查", Description: "检查口令更改最小间隔天数", Level: "高", Category: "口令", Command: `cat /etc/login.defs | grep PASS_MIN_DAYS`},
	{ID: 9, Name: "口令过期警告天数检查", Description: "检查口令过期前警告天数", Level: "中", Category: "口令", Command: `cat /etc/login.defs | grep PASS_WARN_AGE`},
	{ID: 10, Name: "口令复杂度检查", Description: "检查系统口令长度及构成字符要求", Level: "高", Category: "口令", Command: `cat /etc/security/pwquality.conf`},
	{ID: 11, Name: "空口令账号检查", Description: "检查是否存在空口令账号", Level: "极高", Category: "口令", Command: `awk -F: '($2=="")' /etc/shadow`},
	{ID: 12, Name: "口令重复次数检查", Description: "检查口令重复次数限制", Level: "高", Category: "口令", Command: `cat /etc/pam.d/system-auth`},
	
	// 认证类检查 (13-15)
	{ID: 13, Name: "su命令限制检查", Description: "检查是否设置限制su命令用户组", Level: "高", Category: "认证", Command: `cat /etc/pam.d/su | grep -v "^#" | grep -v "^$"`},
	{ID: 14, Name: "登录失败锁定检查", Description: "检查是否设置重复登录失败后锁定时间限制", Level: "高", Category: "认证", Command: `cat /etc/pam.d/system-auth`},
	{ID: 15, Name: "登录失败记录检查", Description: "检查是否开启命令及登录失败记录", Level: "低", Category: "认证", Command: `cat /etc/login.defs | grep -v "^#" | grep -v "^$"`},
	
	// 权限类检查 (16-18)
	{ID: 16, Name: "用户UMASK检查", Description: "检查用户缺省UMASK设置", Level: "中", Category: "权限", Command: `egrep -v '^#|^$' /etc/profile|grep -i "umask"|tail -1`},
	{ID: 17, Name: "重要文件权限检查", Description: "检查passwd、shadow、group等重要文件权限", Level: "高", Category: "权限", Command: `ls -l /etc/passwd /etc/shadow /etc/group`},
	{ID: 18, Name: "日志文件权限检查", Description: "检查日志文件权限设置", Level: "高", Category: "权限", Command: `ls -l /var/log/secure /var/log/messages`},
	
	// 日志类检查 (19-24)
	{ID: 19, Name: "登录日志记录检查", Description: "检查是否记录帐户登录日志", Level: "高", Category: "日志", Command: `ps -ef |grep -E 'syslogd|syslog-ng'|grep -v grep`},
	{ID: 20, Name: "Cron计划任务日志检查", Description: "检查是否记录计划任务日志", Level: "中", Category: "日志", Command: `cat /etc/rsyslog.conf | grep cron`},
	{ID: 21, Name: "远程日志功能检查", Description: "检查是否配置远程日志服务器", Level: "中", Category: "日志", Command: `cat /etc/rsyslog.conf | grep "@"`},
	{ID: 22, Name: "su日志记录检查", Description: "检查是否记录su日志", Level: "中", Category: "日志", Command: `ps -ef |grep -E 'syslogd|syslog-ng'|grep -v grep`},
	{ID: 23, Name: "安全事件日志检查", Description: "检查是否记录安全事件日志", Level: "中", Category: "日志", Command: `ps -ef |grep -E 'syslogd|syslog-ng'|grep -v grep`},
	{ID: 24, Name: "日志轮转配置检查", Description: "检查日志大小和数量配置", Level: "中", Category: "日志", Command: `cat /etc/logrotate.d/syslog | egrep "rotate|size"`},
	
	// 网络类检查 (25-34)
	{ID: 25, Name: "root远程登录检查", Description: "检查是否限制root远程登录", Level: "高", Category: "网络", Command: `cat /etc/ssh/sshd_config`},
	{ID: 26, Name: "SSH服务检查", Description: "检查是否使用ssh替代telnet服务", Level: "高", Category: "网络", Command: `rpm -q telnet-server|grep -v 'is not installed'`},
	{ID: 27, Name: "SSH加密算法检查", Description: "检查SSH是否使用业界认可的加密算法", Level: "高", Category: "网络", Command: `cat /etc/ssh/sshd_config`},
	{ID: 28, Name: "ICMP重定向检查", Description: "检查是否禁止icmp重定向", Level: "低", Category: "网络", Command: `sysctl -n net.ipv4.conf.all.accept_redirects`},
	{ID: 29, Name: "反向路径过滤检查", Description: "检查是否开启反向路径过滤", Level: "低", Category: "网络", Command: `sysctl net.ipv4.conf.all.rp_filter`},
	{ID: 30, Name: "IP转发功能检查", Description: "检查是否关闭IP转发功能", Level: "低", Category: "网络", Command: `cat /etc/sysctl.conf`},
	{ID: 31, Name: "SNMP默认团体字检查", Description: "检查SNMP是否使用默认团体字", Level: "中", Category: "网络", Command: `cat /etc/snmp/snmpd.conf | grep -E "public|private"`},
	{ID: 32, Name: "FTP root登录检查", Description: "检查是否禁止root登录FTP", Level: "中", Category: "网络", Command: `cat /etc/vsftpd/ftpusers | grep root`},
	{ID: 33, Name: "匿名FTP登录检查", Description: "检查是否禁止匿名FTP登录", Level: "高", Category: "网络", Command: `cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable`},
	{ID: 34, Name: "远程登录IP限制检查", Description: "检查是否限制远程登录IP范围", Level: "高", Category: "网络", Command: `cat /etc/hosts.allow /etc/hosts.deny`},
	
	// 服务类检查 (35-36)
	{ID: 35, Name: "危险端口检查", Description: "检查是否关闭不必要端口(139/445)", Level: "高", Category: "服务", Command: `netstat -an | grep -E ":139|:445"`},
	{ID: 36, Name: "不必要服务检查", Description: "检查是否关闭不必要服务", Level: "高", Category: "服务", Command: `chkconfig --list|egrep "amanda|chargen|chargen-udp|cups|cups-lpd|daytime|daytime-udp|echo|echo-udp|eklogin|ekrb5-telnet|finger|gssftp|imap|imaps|ipop2|ipop3|klogin|krb5-telnet|kshell|ktalk|ntalk|rexec|rlogin|rsh|rsync|talk|tcpmux-server|telnet|tftp|time-dgram|time-stream|uucp"`},
	
	// 配置类检查 (37-50)
	{ID: 37, Name: "SSH登录前Banner检查", Description: "检查SSH登录前Banner配置", Level: "中", Category: "配置", Command: `cat /etc/ssh/sshd_config | grep Banner`},
	{ID: 38, Name: "SSH登录后Banner检查", Description: "检查SSH登录后Banner(motd)配置", Level: "低", Category: "配置", Command: `cat /etc/motd`},
	{ID: 39, Name: "潜在危险文件检查", Description: "检查.rhost/.netrc/hosts.equiv等危险文件", Level: "中", Category: "配置", Command: `find / -name ".rhosts" -o -name ".netrc" -o -name "hosts.equiv" 2>/dev/null`},
	{ID: 40, Name: "命令行超时检查", Description: "检查命令行自动超时退出设置", Level: "中", Category: "配置", Command: `cat /etc/profile | grep TMOUT`},
	{ID: 41, Name: "Ctrl+Alt+Del重启检查", Description: "检查是否禁用Ctrl+Alt+Del重启", Level: "低", Category: "配置", Command: `systemctl status ctrl-alt-del.target`},
	{ID: 42, Name: "root环境变量检查", Description: "检查root环境变量安全性", Level: "中", Category: "配置", Command: `echo $PATH | grep "\."`},
	{ID: 43, Name: "历史命令条数检查", Description: "检查历史命令条数限制", Level: "中", Category: "配置", Command: `cat /etc/profile | grep HISTSIZE`},
	{ID: 44, Name: "NTP配置检查", Description: "检查是否配置ntp", Level: "中", Category: "配置", Command: `ps -ef |grep -E 'ntpd|chronyd'|grep -v grep`},
	{ID: 45, Name: "NFS服务安全配置检查", Description: "检查NFS服务安全配置", Level: "中", Category: "配置", Command: `cat /etc/exports | grep root_squash`},
	{ID: 46, Name: "系统Coredump设置检查", Description: "检查系统Coredump设置", Level: "中", Category: "配置", Command: `cat /etc/security/limits.conf | grep core`},
	{ID: 47, Name: "FTP上传umask检查", Description: "检查FTP上传umask设置", Level: "中", Category: "配置", Command: `cat /etc/vsftpd/vsftpd.conf | grep local_umask`},
	{ID: 48, Name: "FTP目录限制检查", Description: "检查FTP目录限制(chroot)配置", Level: "中", Category: "配置", Command: `cat /etc/vsftpd/vsftpd.conf | grep chroot_local_user`},
	{ID: 49, Name: "FTP Banner隐藏检查", Description: "检查FTP Banner版本隐藏", Level: "低", Category: "配置", Command: `cat /etc/vsftpd/vsftpd.conf | grep ftpd_banner`},
	{ID: 50, Name: "Telnet Banner隐藏检查", Description: "检查Telnet Banner版本隐藏", Level: "低", Category: "配置", Command: `cat /etc/issue.net`},
	
	// 网络安全检查 (51-56)
	{ID: 51, Name: "SYN洪水攻击防护检查", Description: "检查是否开启SYN洪水攻击防护", Level: "高", Category: "网络", Command: `sysctl net.ipv4.tcp_syncookies`},
	{ID: 52, Name: "SSH MaxAuthTries检查", Description: "检查SSH单次连接认证尝试次数限制", Level: "高", Category: "网络", Command: `cat /etc/ssh/sshd_config | grep MaxAuthTries`},
	{ID: 53, Name: "SSH登录超时设置检查", Description: "检查SSH登录超时设置", Level: "中", Category: "网络", Command: `cat /etc/ssh/sshd_config | grep ClientAliveInterval`},
	{ID: 54, Name: "SSH协议版本检查", Description: "检查SSH协议版本设置", Level: "高", Category: "网络", Command: `cat /etc/ssh/sshd_config | grep Protocol`},
	{ID: 55, Name: "SSH空闲超时检查", Description: "检查SSH空闲超时设置", Level: "中", Category: "网络", Command: `cat /etc/ssh/sshd_config | grep ClientAliveCountMax`},
	{ID: 56, Name: "SSH登录用户限制检查", Description: "检查SSH登录用户限制", Level: "中", Category: "网络", Command: `cat /etc/ssh/sshd_config | grep -E "AllowUsers|DenyUsers"`},
	
	// 权限和文件检查 (57-62)
	{ID: 57, Name: "SUID/SGID文件检查", Description: "检查并清理SUID/SGID文件", Level: "低", Category: "权限", Command: `find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null`},
	{ID: 58, Name: "世界可写文件检查", Description: "检查世界可写文件", Level: "中", Category: "权限", Command: `find / -type f -perm -002 -exec ls -l {} \; 2>/dev/null | head -20`},
	{ID: 59, Name: "无属主文件检查", Description: "检查无属主文件", Level: "中", Category: "权限", Command: `find / -nouser -o -nogroup -exec ls -l {} \; 2>/dev/null | head -20`},
	{ID: 60, Name: "关键目录权限检查", Description: "检查关键目录权限设置", Level: "高", Category: "权限", Command: `ls -ld /etc /bin /sbin /usr/bin /usr/sbin`},
	{ID: 61, Name: "临时目录权限检查", Description: "检查临时目录权限设置", Level: "中", Category: "权限", Command: `ls -ld /tmp /var/tmp`},
	{ID: 62, Name: "用户主目录权限检查", Description: "检查用户主目录权限", Level: "中", Category: "权限", Command: `ls -la /home`},
	
	// 系统资源和性能检查 (63-68)
	{ID: 63, Name: "磁盘空间占用率检查", Description: "检查磁盘空间占用率", Level: "中", Category: "资源", Command: `df -h`},
	{ID: 64, Name: "内存使用率检查", Description: "检查内存使用率", Level: "低", Category: "资源", Command: `free -m`},
	{ID: 65, Name: "CPU负载检查", Description: "检查CPU负载情况", Level: "低", Category: "资源", Command: `uptime`},
	{ID: 66, Name: "进程数量检查", Description: "检查系统进程数量", Level: "低", Category: "资源", Command: `ps aux | wc -l`},
	{ID: 67, Name: "网络连接数检查", Description: "检查网络连接数", Level: "低", Category: "资源", Command: `netstat -an | wc -l`},
	{ID: 68, Name: "系统负载检查", Description: "检查系统平均负载", Level: "低", Category: "资源", Command: `cat /proc/loadavg`},
	
	// 合规和安全工具检查 (69-72)
	{ID: 69, Name: "入侵检测工具检查", Description: "检查是否安装入侵检测工具", Level: "中", Category: "合规", Command: `which chkrootkit rkhunter 2>/dev/null`},
	{ID: 70, Name: "系统内核补丁检查", Description: "检查系统内核版本和补丁", Level: "高", Category: "合规", Command: `uname -a`},
	{ID: 71, Name: "防病毒软件检查", Description: "检查是否安装防病毒软件", Level: "中", Category: "合规", Command: `ps aux | grep -E "clamav|mcafee|symantec" | grep -v grep`},
	{ID: 72, Name: "系统完整性检查", Description: "检查系统文件完整性", Level: "高", Category: "合规", Command: `rpm -Va | head -20`},
}
func (m model) viewWeakPasswordCheck() string {
	var s strings.Builder

	// 彩色标题
	title := titleStyle.Render("🔍 弱口令检测")
	s.WriteString(title)
	s.WriteString("\n\n")

	// 显示当前选择的字典
	dictPanel := panelStyle.Render(
		infoStyle.Render(" 当前字典 ") + "\n" +
		warningStyle.Render(fmt.Sprintf("→ %s", m.dictionaryFilePath)))
	s.WriteString(dictPanel)
	s.WriteString("\n")

	// Root检测状态显示
	rootStatus := "已禁用"
	rootStyle := successStyle
	if m.enableRootCheck {
		rootStatus = "已启用"
		rootStyle = dangerStyle
	}
	rootPanel := panelStyle.Render(
		infoStyle.Render(" Root用户检测 ") + "\n" +
		rootStyle.Render("→ "+rootStatus))
	s.WriteString(rootPanel)
	s.WriteString("\n")

	// 功能介绍面板
	introPanel := panelStyle.Render(
		highlightStyle.Render(" 功能介绍 ") + "\n" +
		normalStyle.Render("• 自动识别系统用户密码Hash类型 (MD5/SHA256/SHA512/DES)") + "\n" +
		normalStyle.Render("• 支持自定义字典文件进行碰撞检测") + "\n" +
		normalStyle.Render("• 智能性能调度，避免影响业务运行") + "\n" +
		normalStyle.Render("• 支持批量检测和实时进度显示"))
	s.WriteString(introPanel)
	s.WriteString("\n")

	// 系统性能配置信息 - 使用当前配置
	perfPanel := panelStyle.Render(
		infoStyle.Render(" 性能配置 ") + "\n" +
		fmt.Sprintf("并发数: %d  |  批处理: %d  |  CPU限制: %.0f%%",
			m.weakPasswordConfig.MaxConcurrent, m.weakPasswordConfig.BatchSize, m.weakPasswordConfig.CPULimit*100) + "\n" +
		fmt.Sprintf("检查间隔: %v  |  优先级: %s",
			m.weakPasswordConfig.CheckInterval, m.weakPasswordConfig.Priority))
	s.WriteString(perfPanel)
	s.WriteString("\n")

	// 安全警告
	warningPanel := panelStyle.Render(
		dangerStyle.Render(" [!]  安全警告 ") + "\n" +
		warningStyle.Render("• 此功能需要root权限读取/etc/shadow文件") + "\n" +
		warningStyle.Render("• 检测过程会消耗CPU资源，建议在业务低峰期执行") + "\n" +
		warningStyle.Render("• 发现弱口令后请立即要求用户修改密码"))
	s.WriteString(warningPanel)
	s.WriteString("\n")

	// 选项列表
	options := []string{
		"开始弱口令检测",
		"输入字典路径",
		"性能配置调整",
		"返回主菜单",
	}

	for i, option := range options {
		if i == m.cursor {
			line := selectedStyle.Render("[>] " + option)
			s.WriteString(line)
		} else {
			var optionStyle lipgloss.Style
			switch i {
			case 0:
				optionStyle = successStyle
			case 1:
				optionStyle = warningStyle
			case 2:
				optionStyle = infoStyle
			case 3:
				optionStyle = normalStyle
			}
			line := optionStyle.Render("  " + option)
			s.WriteString(line)
		}
		s.WriteString("\n")
	}

	s.WriteString("\n")

	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("↑/↓ 选择选项  Enter 确认  Esc 返回主菜单  q 退出程序"))
	s.WriteString(helpPanel)

	if m.message != "" {
		s.WriteString("\n")
		if strings.Contains(m.message, "成功") || strings.Contains(m.message, "完成") {
			s.WriteString(successStyle.Render("✓ " + m.message))
		} else {
			s.WriteString(warningStyle.Render("[!] " + m.message))
		}
	}

	return s.String()
}

func (m model) viewWeakPasswordResults() string {
	var s strings.Builder
	
	// 如果正在显示进度条，显示进度条界面
	if m.showProgress && m.isProcessing {
		return m.renderProgressBar()
	}
	
	// 彩色标题
	title := titleStyle.Render("弱口令检测结果")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	if len(m.weakPasswordResults) == 0 {
		loadingPanel := warningStyle.Render(" 正在执行弱口令检测，请稍候... ")
		s.WriteString(loadingPanel)
		s.WriteString("\n")
		return s.String()
	}
	
	// 统计结果
	totalUsers := len(m.weakPasswordResults)
	weakUsers := 0
	safeUsers := 0
	errorUsers := 0
	skippedUsers := 0
	
	for _, result := range m.weakPasswordResults {
		switch result.Status {
		case "弱口令":
			weakUsers++
		case "安全":
			safeUsers++
		case "错误":
			errorUsers++
		case "跳过":
			skippedUsers++
		}
	}
	
	// 彩色统计面板
	statsPanel := panelStyle.Render(
		highlightStyle.Render(" 检测结果统计 ") + "\n" +
		dangerStyle.Render(fmt.Sprintf("[!] 弱口令: %d 个", weakUsers)) + "  " +
		successStyle.Render(fmt.Sprintf("[+] 安全: %d 个", safeUsers)) + "  " +
		warningStyle.Render(fmt.Sprintf("[x] 错误: %d 个", errorUsers)) + "  " +
		helpStyle.Render(fmt.Sprintf("[->] 跳过: %d 个", skippedUsers)) + "\n" +
		infoStyle.Render(fmt.Sprintf("总计: %d 个用户", totalUsers)))
	s.WriteString(statsPanel)
	s.WriteString("\n")
	
	// 分页显示逻辑
	const itemsPerPage = 10
	totalPages := (len(m.weakPasswordResults) + itemsPerPage - 1) / itemsPerPage
	currentPage := m.cursor / itemsPerPage
	startIdx := currentPage * itemsPerPage
	endIdx := startIdx + itemsPerPage
	if endIdx > len(m.weakPasswordResults) {
		endIdx = len(m.weakPasswordResults)
	}
	
	// 显示页面信息
	currentPos := m.cursor + 1
	pageInfo := fmt.Sprintf("第 %d/%d 页 (显示 %d-%d 项) | 位置: %d/%d", 
		currentPage+1, totalPages, startIdx+1, endIdx, currentPos, totalUsers)
	s.WriteString(infoStyle.Render(" " + pageInfo + " "))
	s.WriteString("\n\n")
	
	// 详细结果列表
	detailsTitle := highlightStyle.Render(" 详细结果 ")
	s.WriteString(detailsTitle)
	s.WriteString("\n\n")
	
	// 显示当前页的检测结果
	for i := startIdx; i < endIdx; i++ {
		result := m.weakPasswordResults[i]
		prefix := "  "
		if i == m.cursor {
			prefix = selectedStyle.Render("▶ ")
		}
		
		// 状态图标和颜色
		var statusIcon string
		var statusStyle lipgloss.Style
		switch result.Status {
		case "弱口令":
			statusIcon = "[!]"
			statusStyle = dangerStyle
		case "安全":
			statusIcon = "[+]"
			statusStyle = successStyle
		case "错误":
			statusIcon = "[x]"
			statusStyle = warningStyle
		case "跳过":
			statusIcon = "[->]"
			statusStyle = helpStyle
		default:
			statusIcon = "[D]"
			statusStyle = infoStyle
		}
		
		// Hash类型标签
		hashLabel := ""
		if result.HashType != "" {
			hashLabel = fmt.Sprintf("[%s]", result.HashType)
		}
		
		line := fmt.Sprintf("%s%s %s %s %s",
			prefix,
			statusStyle.Render(statusIcon),
			normalStyle.Render(result.Username),
			helpStyle.Render(hashLabel),
			statusStyle.Render(result.Status))
		
		if i == m.cursor {
			s.WriteString(selectedStyle.Render(line))
		} else {
			s.WriteString(line)
		}
		s.WriteString("\n")
		
		// 显示当前选中项的详细信息
		if i == m.cursor {
			s.WriteString("\n")
			
			detailsContent := ""
			
			if result.HashType != "" {
				detailsContent += helpStyle.Render("Hash类型: ") + infoStyle.Render(result.HashType) + "\n"
			}
			
			if result.IsWeak && result.WeakPassword != "" {
				detailsContent += helpStyle.Render("弱口令: ") + dangerStyle.Render(result.WeakPassword) + "\n"
			}
			
			if result.CheckTime > 0 {
				detailsContent += helpStyle.Render("检测耗时: ") + normalStyle.Render(result.CheckTime.String()) + "\n"
			}
			
			if result.HashValue != "" && len(result.HashValue) > 20 {
				shortHash := result.HashValue[:20] + "..."
				detailsContent += helpStyle.Render("Hash值: ") + helpStyle.Render(shortHash) + "\n"
			}
			
			if result.Status == "弱口令" {
				detailsContent += dangerStyle.Render("⚠ 建议: 立即要求用户修改密码！") + "\n"
			}
			
			detailsPanel := borderStyle.Render(detailsContent)
			s.WriteString(detailsPanel)
			s.WriteString("\n")
		}
	}
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("↑/↓ 查看详情  R 重新检测  S 保存报告  F 显示弱口令") + "\n" +
		helpStyle.Render("Esc 返回检测界面  q 退出程序") + "\n" +
		warningStyle.Render("提示: 发现弱口令请立即要求用户修改密码"))
	s.WriteString(helpPanel)
	
	if m.message != "" {
		s.WriteString("\n")
		if strings.Contains(m.message, "成功") || strings.Contains(m.message, "已保存") {
			s.WriteString(successStyle.Render("✓ " + m.message))
		} else {
			s.WriteString(warningStyle.Render("⚠ " + m.message))
		}
	}
	
	return s.String()
}
func (m model) viewWeakPasswordConfig() string {
	var s strings.Builder
	
	// 彩色标题
	title := titleStyle.Render("弱口令检测 - 性能配置")
	s.WriteString(title)
	s.WriteString("\n\n")
	
	// 配置说明面板
	introPanel := panelStyle.Render(
		highlightStyle.Render(" 配置说明 ") + "\n" +
		normalStyle.Render("• 调整检测性能参数以适应不同的系统环境") + "\n" +
		normalStyle.Render("• 高性能系统可以增加并发数和减少间隔时间") + "\n" +
		normalStyle.Render("• 生产环境建议使用较低的CPU限制") + "\n" +
		normalStyle.Render("• 使用 ←/→ 键调整数值，R键重置为默认"))
	s.WriteString(introPanel)
	s.WriteString("\n")
	
	// 当前系统信息
	cpuCount := runtime.NumCPU()
	systemLoad := getSystemLoad()
	sysInfoPanel := panelStyle.Render(
		infoStyle.Render(" 系统信息 ") + "\n" +
		fmt.Sprintf("CPU核心数: %d  |  系统负载: %.2f", cpuCount, systemLoad))
	s.WriteString(sysInfoPanel)
	s.WriteString("\n")
	
	// 配置选项
	configOptions := []struct {
		name        string
		value       string
		description string
		range_info  string
	}{
		{
			"并发检测数",
			fmt.Sprintf("%d", m.weakPasswordConfig.MaxConcurrent),
			"同时进行密码检测的线程数",
			"范围: 1-8",
		},
		{
			"批处理大小",
			fmt.Sprintf("%d", m.weakPasswordConfig.BatchSize),
			"每批处理的密码数量",
			"范围: 10-200",
		},
		{
			"CPU使用限制",
			fmt.Sprintf("%.0f%%", m.weakPasswordConfig.CPULimit*100),
			"最大CPU使用率限制",
			"范围: 10%-80%",
		},
		{
			"检查间隔",
			fmt.Sprintf("%v", m.weakPasswordConfig.CheckInterval),
			"批次间的等待时间",
			"范围: 50ms-1000ms",
		},
		{
			"字典文件",
			m.dictionaryFilePath,
			"当前使用的字典文件",
			"使用 ←/→ 切换字典",
		},
		{
			"保存配置",
			"",
			"保存当前配置并返回",
			"按Enter确认",
		},
	}

	for i, option := range configOptions {
		prefix := "  "
		if i == m.cursor {
			prefix = selectedStyle.Render("▶ ")
		}

		var line string
		if i == 5 { // 保存配置选项
			if i == m.cursor {
				line = selectedStyle.Render(prefix + option.name)
			} else {
				line = successStyle.Render("  " + option.name)
			}
		} else {
			nameStyle := normalStyle
			if i == m.cursor {
				nameStyle = selectedStyle
			}

			// 字典文件选项使用不同颜色
			if i == 4 {
				line = fmt.Sprintf("%s%s: %s",
					prefix,
					warningStyle.Render(option.name),
					warningStyle.Render(option.value))
			} else {
				line = fmt.Sprintf("%s%s: %s",
					prefix,
					nameStyle.Render(option.name),
					highlightStyle.Render(option.value))
			}
		}

		s.WriteString(line)
		s.WriteString("\n")

		// 显示当前选中项的详细信息
		if i == m.cursor && i < 5 {
			detailsContent := helpStyle.Render("描述: ") + normalStyle.Render(option.description) + "\n" +
				helpStyle.Render(option.range_info) + "\n" +
				helpStyle.Render("使用 ←/→ 键调整")

			detailsPanel := borderStyle.Render(detailsContent)
			s.WriteString(detailsPanel)
			s.WriteString("\n")
		}
	}
	
	s.WriteString("\n")
	
	// 性能建议面板
	var recommendationText string
	if systemLoad > 2.0 {
		recommendationText = "系统负载较高，建议降低并发数和增加检查间隔"
	} else if cpuCount >= 8 {
		recommendationText = "多核系统，可以适当增加并发数以提高检测效率"
	} else if cpuCount <= 2 {
		recommendationText = "单核或双核系统，建议使用较低的并发数和CPU限制"
	} else {
		recommendationText = "当前配置适合您的系统环境"
	}
	
	recommendPanel := panelStyle.Render(
		warningStyle.Render(" 性能建议 ") + "\n" +
		normalStyle.Render(recommendationText))
	s.WriteString(recommendPanel)
	s.WriteString("\n")
	
	// 操作说明面板
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("↑/↓ 选择配置项  ←/→ 调整数值  R 重置默认") + "\n" +
		helpStyle.Render("Enter 保存配置  Esc 返回上级  q 退出程序"))
	s.WriteString(helpPanel)
	
	if m.message != "" {
		s.WriteString("\n")
		if strings.Contains(m.message, "成功") || strings.Contains(m.message, "已保存") || strings.Contains(m.message, "已重置") {
			s.WriteString(successStyle.Render("[+] " + m.message))
		} else {
			s.WriteString(warningStyle.Render("[!] " + m.message))
		}
	}
	
	return s.String()
}

// 字典路径输入界面
func (m model) viewWeakPasswordDictInput() string {
	var s strings.Builder

	// 彩色标题
	title := titleStyle.Render("输入字典文件路径")
	s.WriteString(title)
	s.WriteString("\n\n")

	// 当前字典显示
	currentDictPanel := panelStyle.Render(
		infoStyle.Render(" 当前字典 ") + "\n" +
		normalStyle.Render(fmt.Sprintf("→ %s", m.dictionaryFilePath)))
	s.WriteString(currentDictPanel)
	s.WriteString("\n\n")

	// 输入提示
	promptPanel := panelStyle.Render(
		highlightStyle.Render(" 请输入字典文件路径 ") + "\n" +
		helpStyle.Render("• 支持相对路径或绝对路径") + "\n" +
		helpStyle.Render("• 示例: Top1000pass.txt 或 /opt/dicts/passwords.txt"))
	s.WriteString(promptPanel)
	s.WriteString("\n\n")

	// 输入框
	inputLabel := normalStyle.Render("路径: ")
	inputContent := highlightStyle.Render(m.inputValue)
	if m.inputMode {
		inputContent += selectedStyle.Render("█")
	}
	inputLine := inputLabel + inputContent
	s.WriteString(borderStyle.Render(inputLine))
	s.WriteString("\n\n")

	// 错误消息
	if m.message != "" {
		errorPanel := dangerStyle.Render(" [!] " + m.message)
		s.WriteString(errorPanel)
		s.WriteString("\n\n")
	}

	// 操作说明
	helpPanel := panelStyle.Render(
		highlightStyle.Render(" 操作说明 ") + "\n" +
		helpStyle.Render("直接输入路径，完成后按 Enter 确认") + "\n" +
		helpStyle.Render("Esc 取消并返回  q 退出程序"))
	s.WriteString(helpPanel)

	return s.String()
}

// 渲染进度条
func (m model) renderProgressBar() string {
	var s strings.Builder
	
	// 进度条标题
	s.WriteString(titleStyle.Render("执行中"))
	s.WriteString("\n\n")
	
	// 显示当前操作信息
	if m.progressMessage != "" {
		s.WriteString(infoStyle.Render("当前操作: " + m.progressMessage))
		s.WriteString("\n\n")
	}
	
	// 简单的动画效果 - 使用旋转字符
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerIndex := int(time.Now().UnixNano()/100000000) % len(spinner)
	
	spinnerText := fmt.Sprintf("%s 正在执行检测，请稍候...", spinner[spinnerIndex])
	s.WriteString(highlightStyle.Render(spinnerText))
	s.WriteString("\n\n")
	
	// 进度信息（如果有的话）
	if m.progressTotal > 0 {
		percentage := 0
		if m.progressTotal > 0 {
			percentage = (m.progressCurrent * 100) / m.progressTotal
		}
		
		progressInfo := fmt.Sprintf("进度: %d/%d (%d%%)", 
			m.progressCurrent, m.progressTotal, percentage)
		s.WriteString(infoStyle.Render(progressInfo))
		s.WriteString("\n\n")
		
		// 进度条
		barWidth := 40
		filledWidth := 0
		if m.progressTotal > 0 {
			filledWidth = (m.progressCurrent * barWidth) / m.progressTotal
		}
		
		progressBar := "["
		for i := 0; i < barWidth; i++ {
			if i < filledWidth {
				progressBar += "="
			} else if i == filledWidth && m.progressCurrent < m.progressTotal {
				progressBar += ">"
			} else {
				progressBar += " "
			}
		}
		progressBar += "]"
		
		s.WriteString(successStyle.Render(progressBar))
		s.WriteString("\n\n")
	}
	
	// 提示信息
	s.WriteString(helpStyle.Render("检测正在后台执行，请耐心等待..."))
	s.WriteString("\n")
	s.WriteString(helpStyle.Render("按 q 可以退出程序"))
	
	return s.String()
}