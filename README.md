# GetAPI Client Proxy

로컬에서 실행되는 HTTP 리버스 프록시. GetAPI 서버 인증을 자동으로 처리하여 클라이언트 앱이 인증 없이 API를 사용할 수 있게 해준다.

## 동작 방식

```
클라이언트 앱
    │
    ▼
http://getapi/something        ← 로컬 프록시 (포트 80)
    │
    │  X-GetAPI-Key, X-GetAPI-Signature 자동 추가
    ▼
http://localhost:8080/lib/something   ← GetAPI 서버
    │
    ▼
업스트림 API 응답 → 클라이언트로 전달
```

실행 시 Device Flow(RFC 8628)로 인증하며, 발급된 API Key와 Secret Key는 메모리에만 보관한다. API Key는 만료일마다 자정에 자동 갱신된다.

## 설치

### 바이너리 다운로드

**Linux (amd64)**
```bash
curl -L https://github.com/devlib-itsw/getapi-client/releases/latest/download/getapi-proxy_linux_amd64.tar.gz | tar xz
sudo ./getapi-proxy
```

**Linux (arm64)**
```bash
curl -L https://github.com/devlib-itsw/getapi-client/releases/latest/download/getapi-proxy_linux_arm64.tar.gz | tar xz
sudo ./getapi-proxy
```

**macOS (Apple Silicon)**
```bash
curl -L https://github.com/devlib-itsw/getapi-client/releases/latest/download/getapi-proxy_darwin_arm64.tar.gz | tar xz
sudo ./getapi-proxy
```

**macOS (Intel)**
```bash
curl -L https://github.com/devlib-itsw/getapi-client/releases/latest/download/getapi-proxy_darwin_amd64.tar.gz | tar xz
sudo ./getapi-proxy
```

**Windows (PowerShell, 관리자로 실행)**
```powershell
Invoke-WebRequest -Uri "https://github.com/devlib-itsw/getapi-client/releases/latest/download/getapi-proxy_windows_amd64.zip" -OutFile proxy.zip
Expand-Archive proxy.zip
.\getapi-proxy.exe
```

### 소스 빌드
```bash
git clone https://github.com/devlib-itsw/getapi-client.git
cd getapi-client
go build -o getapi-proxy ./proxy.go
```

## 실행

> Linux / macOS는 포트 80 사용을 위해 root 권한 필요
> Windows는 관리자 권한으로 실행

```
sudo ./getapi-proxy
```

실행하면:

1. 로깅 여부 및 경로 선택
2. 브라우저 자동 오픈 → GetAPI 사이트에서 인증 코드 입력
3. 인증 완료 시 `/etc/hosts`에 `getapi` 도메인 자동 등록
4. `http://getapi/...` 로 요청 가능

## 사용법

프록시 실행 후 기존 `localhost:8080` 대신 `http://getapi`로 요청:

```bash
# GET
curl http://getapi/my-api/v1/users

# POST
curl -X POST http://getapi/my-api/v1/data \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'
```

인증 헤더(`X-GetAPI-Key`, `X-GetAPI-Timestamp`, `X-GetAPI-Signature`)는 프록시가 자동으로 추가한다.

## 로깅

실행 시 로깅 여부를 선택할 수 있다. 로그는 터미널과 파일에 동시 출력된다.

```
로깅 사용? (y/n): y
로그 경로 (엔터: .getapi-log/): [엔터]
[✓] 로그 파일: .getapi-log/2026-04-18.log
```

로그 형식:
```
2026/04/18 13:00:01 200  GET /my-api/v1/users (42ms)
2026/04/18 13:00:02 404  GET /my-api/v1/unknown (11ms)
```

## 보안

- API Key / Secret Key는 **메모리에만 보관** (파일 저장 없음)
- 요청마다 HMAC-SHA256 서명 생성 (Replay Attack 방지)
- 타임스탬프 기반 ±5분 유효 검증
- API Key는 7일마다 자동 갱신 (rotation token 방식)
- 종료 시 `/etc/hosts` 항목 자동 제거

## 요구사항

- GetAPI 서버가 `localhost:8080`에서 실행 중이어야 함
- Linux: `xclip` 또는 `xsel` 설치 시 인증 코드 클립보드 자동 복사
