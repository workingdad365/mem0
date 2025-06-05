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

# OpenMemory MCP JWT 인증 및 토큰 발급 사용법

OpenMemory MCP 서버는 JWT (JSON Web Token) 기반의 Bearer 토큰 인증을 사용합니다. 이 문서는 JWT 토큰을 생성하고 MCP 세션 연결 시 사용하는 방법을 안내합니다.

---

## JWT (JSON Web Token) 기반 인증 개요

-   **상태 비저장(Stateless)**: 서버는 토큰 자체를 저장하지 않고, 각 요청에 포함된 토큰을 실시간으로 검증함. (추후 Azure APIM으로 대체)
-   **RSA 키 페어 사용**:
    -   `api/private_key.pem` (개인키): JWT 토큰 서명에 사용. **절대로 외부에 노출되어서는 안 됨.**
    -   `api/public_key.pem` (공개키): 서버가 JWT 토큰의 서명을 검증하는 데 사용.
-   **토큰 내용**: 토큰에는 `user_id`, `client_name`, 만료 시간 (`exp`), 발급자 (`iss`), 대상 (`aud`) 등의 정보(클레임)가 포함됨.

---

## 1. JWT 토큰 생성 방법

모든 JWT 토큰은 `openmemory/api` 디렉토리에 있는 `create_token.py` 스크립트를 사용하여 생성.
테스트 용이라 API를 통한 발급 같은 거 없음

**명령어 형식:**

```bash
cd api
python create_token.py --user-id YOUR_USER_ID --client-name CLIENT_NAME
```

-   `--user-id YOUR_USER_ID`: 토큰을 발급할 사용자의 ID를 지정. 이 아이디 기준으로 메모리가 저장됨 (예: `myid`)
-   `--client-name CLIENT_NAME`: 토큰을 사용할 클라이언트의 이름을 지정. (예: `openmemory`)
-   `--admin` (선택 사항): 관리자 권한을 가진 토큰을 생성하려면 이 플래그를 추가. (딱히 용도는 없음)
    ```bash
    python create_token.py --user-id myid --client-name openmemory --admin
    ```

**스크립트 실행 시 동작:**

1.  `api/private_key.pem` 및 `api/public_key.pem` 파일이 존재하지 않으면, 스크립트가 새로운 RSA 키 페어를 생성하여 이 두 파일에 저장함.
2.  이미 키 파일들이 존재하면, 해당 키들을 사용하여 토큰을 생성.
3.  생성된 JWT 토큰이 터미널에 출력됨. 이 토큰을 복사하여 API 요청 시 사용.

**중요:**
-   최초 실행 시 또는 키 페어를 재생성하고 싶을 때 기존 `api/private_key.pem`과 `api/public_key.pem` 파일을 삭제 후 스크립트를 실행하면 새 키 페어가 생성됨.

---

## 2. MCP 세션 연결 시 인증

MCP 클라이언트가 서버에 세션을 맺거나 API를 호출할 때, 생성된 JWT 토큰을 HTTP `Authorization` 헤더에 `Bearer` 스킴으로 전달해야 함.

**사용 예시 (MCP 세션 연결 또는 API 호출):**

```http
POST /mcp/openmemory/mcp/YOUR_USER_ID HTTP/1.1
Host: localhost:8765
Authorization: Bearer <생성된_JWT_토큰>
Content-Type: application/json

{ /* MCP 초기화용 JSON-RPC payload 또는 API 요청 본문 (필요시) */ }
```

-   `<생성된_JWT_토큰>` 부분에 `create_token.py` 실행 시 출력된 실제 토큰 값을 넣음.
-   `YOUR_USER_ID`는 토큰에 포함된 사용자 ID와 일치해야 함.
-   인증 실패 (토큰 누락, 유효하지 않은 서명, 만료된 토큰 등) 시 서버는 HTTP 401 Unauthorized 에러를 반환.

---

## 참고

-   JWT 토큰은 만료 시간(`exp` 클레임)을 가짐. `create_token.py` 스크립트에서 `--expires-days` 인자를 통해 만료일을 설정할 수 있으며, 기본값은 30일임.
-   `api/private_key.pem` 파일은 매우 중요하므로 안전하게 보관해야 함. 이 파일이 유출되면 누구나 유효한 토큰을 생성할 수 있게 됨.
-   서버의 `api/public_key.pem` 파일이 변경되거나 접근 불가능하게 되면, 이전에 해당 공개키와 쌍을 이루는 개인키로 서명된 모든 JWT 토큰은 더 이상 유효하지 않게 됨.
-   관리자 토큰은 강력한 권한을 가지므로 특히 주의해서 관리해야 합니다.