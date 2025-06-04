### qdrant 실행
서버도 도커로 실행하면 상관 없는데 
qdrant만 도커로 실행하고, 서버는 로컬에서 따로 실행시킬 때는
mem0_store 의 주소를 /etc/hosts 에 넣어 놓고 실행해야함.

```
127.0.0.1 mem0_store
```

```
docker compose up -d mem0_store
```

### api 서버 / ui 공통 환경
```
make env
```

이후 api, ui 디렉토리에 생성된 .env 적절히 수정

ui 의 .env 는 대략 다음과 같은 형태

```
NEXT_PUBLIC_API_URL=http://localhost:8765
NEXT_PUBLIC_USER_ID=drasys
```

### api 서버 환경
```
cd api
pip install -r requirements.txt
```

### api 서버 실행
```
uvicorn main:app --host 0.0.0.0 --port 8765 --log-level debug
```

### ui 환경
```
cd ui
pnpm install
pnpm build
```

### ui 실행
```
DEBUG=* pnpm dev
```

혹은

```
pnmp start
```



### qdrant 대시보드

http://localhost:6333/dashboard

---

# OpenMemory MCP 인증/토큰 발급 사용 예시

OpenMemory MCP 서버에서 **관리자 토큰**과 **일반 사용자 토큰(API 키)**을 생성하고 사용하는 방법을 안내합니다.

---

## 1. 관리자 토큰 생성 및 사용

관리자 토큰은 API 키 관리(생성/조회/폐기) 등 관리자 권한이 필요한 작업에 사용됩니다.

### 생성 방법
```bash
cd /home/drasys/project/mem0/openmemory/api
python create_admin_token.py <user_id> --description "관리자 토큰 설명" --expires-in-days 365
```
- `<user_id>`: 관리자 권한을 부여할 사용자 ID(예: `admin`)
- `--description`: 토큰 용도/설명
- `--expires-in-days`: 만료일(일 단위, 0이면 무기한)

#### 예시
```bash
python create_admin_token.py admin --description "운영자 전용 마스터키" --expires-in-days 365
```

### 사용 예시 (API 키 관리)

- **API 키 생성**
```http
POST /api-keys/?admin_token=<관리자_토큰>
{
  "user_id": "user1",
  "description": "모바일앱용 키",
  "expires_in_days": 30
}
```
- **API 키 목록 조회**
```http
GET /api-keys/?user_id=user1&admin_token=<관리자_토큰>
```
- **API 키 폐기**
```http
DELETE /api-keys/<token_id>?admin_token=<관리자_토큰>
```

---

## 2. 일반 사용자 토큰(API 키) 생성 및 사용

사용자 토큰은 MCP 클라이언트가 초기 연결(인증) 시 사용합니다.

### 생성 방법
```bash
cd /home/drasys/project/mem0/openmemory/api
python create_user_token.py <user_id> --description "토큰 설명" --expires-in-days 30
```
- `<user_id>`: 토큰을 발급할 사용자 ID(예: `user1`)
- `--description`: 토큰 용도/설명
- `--expires-in-days`: 만료일(일 단위, 0이면 무기한)

#### 예시
```bash
python create_user_token.py user1 --description "모바일앱 전용 키" --expires-in-days 60
```

### 사용 예시 (MCP 최초 세션 연결)

```http
POST /mcp/openmemory/sse/user1 HTTP/1.1
Host: localhost:8765
X-API-Key: <생성된_토큰>
Content-Type: application/json

{
  // MCP 초기화용 JSON-RPC payload
}
```
- 인증 토큰은 반드시 헤더(`X-API-Key`)로 전달해야 합니다.

---

## 참고
- 모든 토큰 생성 시 `--name` 대신 `--description`을 사용하세요. (`--name`도 호환)
- 관리자 토큰은 반드시 안전하게 보관하세요.
- 기존 DB를 삭제하고 새로 만들 경우, 마이그레이션 없이 바로 사용 가능합니다.