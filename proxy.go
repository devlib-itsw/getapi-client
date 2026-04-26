package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ─── 설정 ────────────────────────────────────────────

const LocalDomain = "getapi"

var (
	baseURL = "http://getapi.lol"
	authURL = baseURL + "/auth/api-key"
)

const banner = `
  ____      _      _     ____   ___
 / ___| ___| |_   / \   |  _ \ |_ _|
| |  _ / _ \ __| / _ \  | |_) | | |
| |_| |  __/ |_ / ___ \ |  __/  | |
 \____|\___|\__/_/   \_\|_|    |___|

 >> Proxy Server is initializing...
`

// ─── 타입 ────────────────────────────────────────────

type Config struct {
	APIKey        string
	SecretKey     string
	RotationToken string
	ExpiredDate   string
}

type SafeConfig struct {
	mu  sync.RWMutex
	cfg Config
}

func (s *SafeConfig) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *SafeConfig) Set(c Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
}

type apiKeyResp struct {
	APIKey        string `json:"api_key"`
	ExpiredDate   string `json:"expired_date"`
	RotationToken string `json:"rotation_token"`
}

type deviceCodeResp struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type devicePollResp struct {
	Status        string `json:"status"`
	APIKey        string `json:"api_key"`
	RotationToken string `json:"rotation_token"`
	SecretKey     string `json:"secret_key"`
	ExpiredDate   string `json:"expired_date"`
}

// ─── HTTP 클라이언트 ──────────────────────────────────

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// ─── 로거 ────────────────────────────────────────────

var logger *log.Logger

func setupLogger(reader *bufio.Reader) {
	fmt.Print("로깅 사용? (y/n): ")
	answer, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(answer)) != "y" {
		logger = log.New(io.Discard, "", 0)
		return
	}

	fmt.Print("로그 경로 (엔터: .getapi-log/): ")
	dir, _ := reader.ReadString('\n')
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = ".getapi-log"
	}

	os.MkdirAll(dir, 0755)
	filename := filepath.Join(dir, time.Now().Format("2006-01-02")+".log")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("[!] 로그 파일 생성 실패: %v\n", err)
		logger = log.New(os.Stdout, "", log.LstdFlags)
		return
	}

	logger = log.New(io.MultiWriter(os.Stdout, f), "", log.LstdFlags)
	fmt.Printf("[✓] 로그 파일: %s\n\n", filename)
}

// ─── 서명 ────────────────────────────────────────────

func sign(secret string, body []byte, timestamp string) string {
	msg := append(body, []byte(timestamp)...)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(msg)
	return hex.EncodeToString(h.Sum(nil))
}

// ─── API 키 갱신 ──────────────────────────────────────

func renewAPIKey(rotationToken, secretKey string) (*apiKeyResp, error) {
	body, _ := json.Marshal(map[string]string{"rotation_token": rotationToken})
	req, _ := http.NewRequest("POST", authURL, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	ts := time.Now().UTC().Format(time.RFC3339)
	req.Header.Set("X-GetAPI-Timestamp", ts)
	req.Header.Set("X-GetAPI-Signature", sign(secretKey, body, ts))

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, b)
	}

	var result apiKeyResp
	json.NewDecoder(resp.Body).Decode(&result)
	return &result, nil
}

func checkAndRenew(sc *SafeConfig) {
	cfg := sc.Get()
	if cfg.ExpiredDate == "" || cfg.RotationToken == "" {
		return
	}

	expiry, err := time.Parse("2006-01-02", cfg.ExpiredDate)
	if err != nil {
		return
	}

	// 로컬 시간 기준 오늘 날짜
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	if today.Before(expiry) {
		return
	}

	fmt.Println("[*] API Key 만료 — 갱신 중...")
	result, err := renewAPIKey(cfg.RotationToken, cfg.SecretKey)
	if err != nil {
		fmt.Printf("[!] 갱신 실패: %v\n", err)
		return
	}

	rt := cfg.RotationToken
	if result.RotationToken != "" {
		rt = result.RotationToken
	}
	sc.Set(Config{
		APIKey:        result.APIKey,
		SecretKey:     cfg.SecretKey,
		RotationToken: rt,
		ExpiredDate:   result.ExpiredDate,
	})
	fmt.Printf("[✓] 갱신 완료. 만료일: %s\n", result.ExpiredDate)
}

// ─── 자정 갱신 고루틴 ─────────────────────────────────

func startMidnightChecker(sc *SafeConfig) {
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
			time.Sleep(next.Sub(now))
			time.Sleep(time.Duration(rand.Intn(301)) * time.Second) // jitter
			checkAndRenew(sc)
		}
	}()
}

// ─── Device Flow ──────────────────────────────────────

func deviceFlow(sc *SafeConfig) error {
	req, _ := http.NewRequest("POST", baseURL+"/auth/device/code", nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("device code 요청 실패: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("device code 오류 %d: %s", resp.StatusCode, b)
	}

	var dc deviceCodeResp
	json.NewDecoder(resp.Body).Decode(&dc)

	verifyURL := baseURL + dc.VerificationURL
	copyToClipboard(dc.UserCode)
	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  Visit: %s\n  Code:  %s  (클립보드에 복사됨)\n  유효시간: %d초\n", verifyURL, dc.UserCode, dc.ExpiresIn)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	openBrowser(verifyURL)

	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	interval := time.Duration(dc.Interval) * time.Second

	for time.Now().Before(deadline) {
		time.Sleep(interval)

		pollReq, _ := http.NewRequest("GET", baseURL+"/auth/device/poll/"+dc.DeviceCode, nil)
		pollResp, err := httpClient.Do(pollReq)
		if err != nil {
			continue
		}

		var poll devicePollResp
		json.NewDecoder(pollResp.Body).Decode(&poll)
		pollResp.Body.Close()

		switch poll.Status {
		case "pending":
			fmt.Print(".")
		case "approved":
			sc.Set(Config{
				APIKey:        poll.APIKey,
				SecretKey:     poll.SecretKey,
				RotationToken: poll.RotationToken,
				ExpiredDate:   poll.ExpiredDate,
			})
			fmt.Printf("\n[✓] 인증 완료. 만료일: %s\n\n", poll.ExpiredDate)
			return nil
		case "expired":
			return fmt.Errorf("device code 만료")
		default:
			return fmt.Errorf("알 수 없는 상태: %s", poll.Status)
		}
	}

	return fmt.Errorf("device flow 시간 초과")
}

// ─── OS 유틸 ─────────────────────────────────────────

func copyToClipboard(text string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("clip")
	case "darwin":
		cmd = exec.Command("pbcopy")
	default: // linux
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return
		}
	}
	cmd.Stdin = strings.NewReader(text)
	cmd.Run()
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

func hostsPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

func addHost() {
	content, _ := os.ReadFile(hostsPath())
	if strings.Contains(string(content), LocalDomain) {
		return
	}
	f, err := os.OpenFile(hostsPath(), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[!] hosts 등록 실패 (관리자 권한 필요): %v\n", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "\n127.0.0.1 %s\n", LocalDomain)
}

func removeHost() {
	content, _ := os.ReadFile(hostsPath())
	var lines []string
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.Contains(line, LocalDomain) {
			lines = append(lines, line)
		}
	}
	os.WriteFile(hostsPath(), []byte(strings.Join(lines, "\n")), 0644)
}

func availablePort(preferred int) string {
	addr := fmt.Sprintf(":%d", preferred)
	l, err := net.Listen("tcp", addr)
	if err == nil {
		l.Close()
		return addr
	}
	// 선호 포트 사용 불가 → 랜덤 포트
	l, err = net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("사용 가능한 포트를 찾을 수 없습니다: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	fmt.Printf("[!] 포트 %d 사용 중. 대체 포트 %d 사용\n", preferred, port)
	return fmt.Sprintf(":%d", port)
}

func requireAdmin() {
	switch runtime.GOOS {
	case "windows":
		f, err := os.OpenFile(hostsPath(), os.O_WRONLY, 0644)
		if err != nil {
			exitWithError("관리자 권한으로 실행해주세요. (우클릭 → 관리자로 실행)")
		}
		f.Close()
	default:
		if os.Geteuid() != 0 {
			exitWithError("root 권한이 필요합니다. (sudo ./getapi-proxy)")
		}
	}
}

// ─── 프록시 핸들러 ────────────────────────────────────

func proxy(w http.ResponseWriter, req *http.Request, sc *SafeConfig) {
	targetURL := baseURL + "/lib" + req.URL.Path
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}

	body, _ := io.ReadAll(req.Body)
	req.Body.Close()

	cfg := sc.Get()
	ts := time.Now().UTC().Format(time.RFC3339)

	proxyReq, err := http.NewRequest(req.Method, targetURL, bytes.NewBuffer(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	for k, vs := range req.Header {
		for _, v := range vs {
			proxyReq.Header.Add(k, v)
		}
	}
	proxyReq.Header.Set("X-GetAPI-Key", cfg.APIKey)
	proxyReq.Header.Set("X-GetAPI-Timestamp", ts)
	proxyReq.Header.Set("X-GetAPI-Signature", sign(cfg.SecretKey, body, ts))

	start := time.Now()
	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		logger.Printf("ERR  %s %s — %v", req.Method, req.URL.Path, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logger.Printf("%d  %s %s (%dms)", resp.StatusCode, req.Method, req.URL.Path, time.Since(start).Milliseconds())

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ─── main ────────────────────────────────────────────

func exitWithError(format string, args ...any) {
	fmt.Printf("\n[!] "+format+"\n", args...)
	fmt.Print("\n계속하려면 Enter를 누르세요...")
	fmt.Scanln()
	os.Exit(1)
}

func main() {
	requireAdmin()

	rand.Seed(time.Now().UnixNano())
	fmt.Print(banner)

	reader := bufio.NewReader(os.Stdin)
	setupLogger(reader)

	sc := &SafeConfig{}
	if err := deviceFlow(sc); err != nil {
		exitWithError("Device Flow 실패: %v", err)
	}

	cfg := sc.Get()
	if cfg.SecretKey == "" {
		exitWithError("SecretKey가 설정되지 않았습니다. 서버에서 SecretKey를 발급받아 설정해주세요.")
	}

	checkAndRenew(sc)
	startMidnightChecker(sc)
	addHost()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		removeHost()
		os.Exit(0)
	}()

	port := availablePort(80)
	fmt.Printf("Running on http://%s%s\n", LocalDomain, port)
	if err := http.ListenAndServe(port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy(w, r, sc)
	})); err != nil {
		exitWithError("서버 실행 실패: %v", err)
	}
}
