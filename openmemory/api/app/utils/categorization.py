import logging
from typing import List

from dotenv import load_dotenv
from openai import AzureOpenAI
from pydantic import BaseModel
from tenacity import retry, stop_after_attempt, wait_exponential
from app.utils.prompts import MEMORY_CATEGORIZATION_PROMPT
import os
import json
from sqlalchemy import text

load_dotenv()

# 기본 설정값 정의 (모듈 레벨에서 설정)
DEFAULT_CONFIG = {
    "llm": {
        "config": {
            "model": "gpt-4.1-mini",
            "temperature": 0,
            "azure_kwargs": {
                "azure_endpoint": os.environ.get("AZURE_ENDPOINT", ""),
                "api_key": os.environ.get("AZURE_OPENAI_API_KEY", ""),
                "api_version": "2024-10-21",
                "azure_deployment": os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1-mini")
            }
        }
    }
}

# Azure OpenAI 클라이언트 설정
def get_azure_openai_client():
    """
    Azure OpenAI 클라이언트를 생성.
    """
    # 환경 변수에서 직접 설정 로드
    azure_endpoint = os.environ.get("AZURE_ENDPOINT", "")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    api_version = "2024-10-21"
    
    return AzureOpenAI(
        azure_endpoint=azure_endpoint,
        api_key=api_key,
        api_version=api_version
    )

# Azure OpenAI 클라이언트 초기화
azure_openai_client = get_azure_openai_client()

class MemoryCategories(BaseModel):
    categories: List[str]


def get_config_from_db():
    """
    데이터베이스에서 설정을 로드하는 함수.
    순환 참조를 피하기 위해 함수 내에서만 임포트.
    """
    try:
        from app.database import SessionLocal
        
        # 여기서는 ConfigModel을 직접 임포트하지 않고 동적으로 접근
        db = SessionLocal()
        try:
            # SQLAlchemy text() 함수로 SQL 쿼리 감싸기
            # config 테이블 존재 여부 확인
            result = db.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='config'")).fetchone()
            if result:
                # config 테이블이 존재하는 경우에만 쿼리 실행
                result = db.execute(text("SELECT config FROM config LIMIT 1")).fetchone()
                if result and result[0]:
                    return result[0]
            else:
                logging.info("config 테이블이 존재하지 않습니다. 기본 설정을 사용합니다.")
        finally:
            db.close()
    except Exception as e:
        logging.error(f"설정 로드 중 오류 발생: {e}")
    
    # 기본 설정 반환
    return DEFAULT_CONFIG


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=15))
def get_categories_for_memory(memory: str) -> List[str]:
    try:
        messages = [
            {"role": "system", "content": MEMORY_CATEGORIZATION_PROMPT},
            {"role": "user", "content": memory}
        ]

        # 설정 로드
        config = get_config_from_db()
        
        llm_config = config.get("llm", {}).get("config", {})
        model = llm_config.get("model", "gpt-4.1-mini")
        azure_kwargs = llm_config.get("azure_kwargs", {})
        deployment = azure_kwargs.get("azure_deployment", model)
        temperature = llm_config.get("temperature", 0)

        # Azure OpenAI API 설정값 로깅
        azure_endpoint = os.environ.get("AZURE_ENDPOINT", "")
        api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
        api_version = "2024-10-21"
        
        logging.info(f"Azure OpenAI 설정 - Endpoint: {azure_endpoint[:10] if azure_endpoint else '없음'}..., API Key: {api_key[:5] if api_key else '없음'}..., API Version: {api_version}, Deployment: {deployment}")
        
        # Azure OpenAI API 호출 시 타임아웃 설정 추가
        try:
            completion = azure_openai_client.chat.completions.create(
                model=deployment,
                messages=messages,
                temperature=temperature,
                response_format={"type": "json_object"},
                timeout=30.0  # 타임아웃 30초 설정
            )
        except Exception as api_error:
            logging.error(f"[ERROR] Azure OpenAI API 호출 오류: {api_error}")
            # 엔드포인트 정보 로깅
            azure_endpoint = os.environ.get("AZURE_ENDPOINT", "")
            logging.error(f"[ERROR] Azure OpenAI Endpoint: {azure_endpoint}")
            raise

        # JSON 응답 파싱
        content = completion.choices[0].message.content
        parsed_json = json.loads(content)
        categories = parsed_json.get("categories", [])
        
        return [cat.strip().lower() for cat in categories]

    except Exception as e:
        logging.error(f"[ERROR] Failed to get categories: {e}")
        try:
            logging.debug(f"[DEBUG] Raw response: {completion.choices[0].message.content}")
        except Exception as debug_e:
            logging.debug(f"[DEBUG] Could not extract raw response: {debug_e}")
        # 오류 발생 시 빈 카테고리 목록 반환하여 실패해도 계속 진행되도록 함
        return []
