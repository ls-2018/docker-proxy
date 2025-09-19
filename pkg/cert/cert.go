package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"docker-proxy/pkg/log"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var tmpDir = ""

func init() {
	tmpDir, _ = ioutil.TempDir("", "docker-proxy")
}

// 写入 PEM 文件
func writePem(filename, pemType string, bytes []byte) {
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	pem.Encode(f, &pem.Block{
		Type:  pemType,
		Bytes: bytes,
	})
}

func prepareCa() (*x509.Certificate, *rsa.PrivateKey) {
	// 1️⃣ 生成 CA 私钥
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	// 2️⃣ 创建 CA 证书模板
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"docker.proxy"},
			CommonName:   "docker.proxy",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0), // 100年有效期
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	// 3️⃣ 自签 CA 证书
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}

	// 写入 CA 私钥和证书
	writePem(filepath.Join(tmpDir, "ca.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))
	writePem(filepath.Join(tmpDir, "ca.crt"), "CERTIFICATE", caCertBytes)

	installCALinux(filepath.Join(tmpDir, "ca.crt"))
	return caTemplate, caKey

}

type DomainSigns struct {
	Crt []byte
	Key []byte
}

func signDomain(domains []string, ca *x509.Certificate, caKey *rsa.PrivateKey) []DomainSigns {
	var ds []DomainSigns

	for _, domain := range domains {
		// 4️⃣ 生成 docker.io 私钥
		serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			panic(err)
		}

		// 5️⃣ 创建 docker.io 证书模板
		serverTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				Organization: []string{"docker.proxy.mock"},
				CommonName:   domain,
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(1, 0, 0), // 1年有效
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:    []string{domain},
		}

		// 6️⃣ 用 CA 签名 docker.io 证书
		serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
		if err != nil {
			panic(err)
		}
		// 写入 私钥和证书
		ds = append(ds, DomainSigns{
			Crt: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: serverCertBytes,
			}),
			Key: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
			}),
		})
	}

	return ds
}

func GenerateCert(domains []string) []DomainSigns {
	ca, caKey := prepareCa()
	return signDomain(domains, ca, caKey)
}

func installCALinux(caPath string) {
	// 判断发行版（Debian/Ubuntu vs CentOS/RHEL）
	if _, err := os.Stat("/usr/local/share/ca-certificates/"); err == nil {
		// Debian/Ubuntu
		run("sudo", "cp", caPath, "/usr/local/share/ca-certificates/")
		run("sudo", "update-ca-certificates")
		log.L.Println("✅ 已安装 CA 到 Debian/Ubuntu 系统证书库")
	} else if _, err := os.Stat("/etc/pki/ca-trust/source/anchors/"); err == nil {
		// CentOS/RHEL
		run("sudo", "cp", caPath, "/etc/pki/ca-trust/source/anchors/")
		run("sudo", "update-ca-trust", "extract")
		log.L.Println("✅ 已安装 CA 到 CentOS/RHEL 系统证书库")
	} else {
		log.L.Fatal("❌ 未检测到支持的 Linux 证书目录")
	}
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.L.Fatalf("执行命令失败: %s %v, 错误: %v", name, args, err)
	}
}

func check() {
	caPath := filepath.Join(tmpDir, "ca.crt")
	// 加载系统根证书
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		log.L.Fatalf("加载系统证书池失败: %v", err)
	}

	log.L.Println("系统证书池包含的部分证书：")
	for i, cert := range sysPool.Subjects() {
		//if i >= 5 { // 只打印前5个，避免太多
		//	break
		//}
		log.L.Printf("证书[%d]: %s\n", i+1, cert)
	}

	// 检查自定义 CA 是否已加入系统
	caData, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.L.Printf("警告: 无法读取 %s: %v", caPath, err)
		return
	}

	block, _ := pem.Decode(caData)
	if block == nil {
		log.L.Fatalf("解析 PEM 失败: %s", caPath)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.L.Fatalf("解析证书失败: %v", err)
	}

	// 遍历系统证书池，检查是否包含你的 CA
	found := false
	for _, sysCert := range sysPool.Subjects() {
		if string(sysCert) == string(caCert.RawSubject) {
			found = true
			break
		}
	}

	if found {
		log.L.Println("✅ 系统证书池已经包含你的 CA")
	} else {
		log.L.Println("❌ 系统证书池没有找到你的 CA")
	}
}

func LoadCert(ds []DomainSigns) *tls.Config {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, caFile := range []string{filepath.Join(tmpDir, "ca.crt")} {
		caPEM, _ := os.ReadFile(caFile)
		rootCAs.AppendCertsFromPEM(caPEM)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
		RootCAs:      rootCAs,
	}
	for _, d := range ds {
		pair, err := tls.X509KeyPair(d.Crt, d.Key)
		if err != nil {
			log.L.Fatal(err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, pair)

	}
	return tlsConfig

}
