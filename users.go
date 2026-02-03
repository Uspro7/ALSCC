package main

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// 获取系统用户列表
func getSystemUsers() ([]User, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []User
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		
		if len(fields) < 7 {
			continue
		}

		username := fields[0]
		uidStr := fields[2]
		shell := fields[6]

		// 跳过root用户
		if username == "root" {
			continue
		}

		// 解析UID
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}

		// 只处理UID >= 1000的用户
		if uid < 1000 {
			continue
		}

		// 过滤掉nologin和false shell的用户
		if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") {
			continue
		}

		// 获取密码最后修改时间
		lastChanged, daysUsed := getPasswordAge(username)

		user := User{
			Username:    username,
			UID:         uid,
			Shell:       shell,
			LastChanged: lastChanged,
			DaysUsed:    daysUsed,
			Selected:    false,
		}

		users = append(users, user)
	}

	return users, scanner.Err()
}

// 获取系统用户列表（可选择是否包含root）
func getSystemUsersWithRoot(includeRoot bool) ([]User, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []User
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")

		if len(fields) < 7 {
			continue
		}

		username := fields[0]
		uidStr := fields[2]
		shell := fields[6]

		// 根据参数决定是否跳过root用户
		if username == "root" && !includeRoot {
			continue
		}

		// 解析UID
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}

		// root用户特殊处理
		if username == "root" && includeRoot {
			// 获取密码使用天数
			lastChanged, daysUsed := getPasswordAge(username)
			user := User{
				Username:    username,
				UID:         uid,
				Shell:       shell,
				LastChanged: lastChanged,
				DaysUsed:    daysUsed,
				Selected:    false,
			}
			users = append(users, user)
			continue
		}

		// 只处理UID >= 1000的用户
		if uid < 1000 {
			continue
		}

		// 过滤掉nologin和false shell的用户
		if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") {
			continue
		}

		// 获取密码最后修改时间
		lastChanged, daysUsed := getPasswordAge(username)

		user := User{
			Username:    username,
			UID:         uid,
			Shell:       shell,
			LastChanged: lastChanged,
			DaysUsed:    daysUsed,
			Selected:    false,
		}

		users = append(users, user)
	}

	return users, scanner.Err()
}

// 获取密码使用天数
func getPasswordAge(username string) (time.Time, int) {
	cmd := exec.Command("chage", "-l", username)
	output, err := cmd.Output()
	if err != nil {
		return time.Now(), 0
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Last password change") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				dateStr := strings.TrimSpace(parts[1])
				if dateStr == "never" {
					return time.Now(), 999 // 从未修改过密码
				}
				
				// 尝试解析日期
				lastChanged, err := time.Parse("Jan 02, 2006", dateStr)
				if err != nil {
					// 尝试其他日期格式
					lastChanged, err = time.Parse("2006-01-02", dateStr)
					if err != nil {
						return time.Now(), 0
					}
				}
				
				daysUsed := int(time.Since(lastChanged).Hours() / 24)
				return lastChanged, daysUsed
			}
		}
	}
	
	return time.Now(), 0
}

// 检查密码过期时间
func checkPasswordExpiry(m *model) error {
	// 重新获取用户密码信息
	for i, user := range m.users {
		lastChanged, daysUsed := getPasswordAge(user.Username)
		m.users[i].LastChanged = lastChanged
		m.users[i].DaysUsed = daysUsed
	}
	return nil
}