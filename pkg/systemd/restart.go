package systemd

import (
	"docker-proxy/pkg/log"
	"os/exec"
)

// checkServiceExists 判断服务是否存在
func checkServiceExists(service string) bool {
	cmd := exec.Command("systemctl", "status", service)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// restartService 重启服务
func restartService(service string) error {
	cmd := exec.Command("systemctl", "restart", service)
	return cmd.Run()
}

func Restart(services []string) {
	for _, svc := range services {
		if checkServiceExists(svc) {
			log.L.Printf("%s 服务存在，正在重启...\n", svc)
			if err := restartService(svc); err != nil {
				log.L.Printf("重启 %s 失败: %v\n", svc, err)
			} else {
				log.L.Printf("%s 已重启成功\n", svc)
			}
		} else {
			log.L.Printf("%s 服务不存在，跳过\n", svc)
		}
	}
}
