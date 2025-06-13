"""
OpenMemory 애플리케이션을 위한 공통 로깅 유틸리티
콘솔 로깅 및 파일 로깅(주석 처리됨) 기능을 제공.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from datetime import datetime

# 로그 디렉토리 설정
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)

# 로그 파일 경로 설정
LOG_FILE = os.path.join(LOG_DIR, f'openmemory_{datetime.now().strftime("%Y%m%d")}.log')

# 로그 포맷 설정 - 타임스탬프, 로그 레벨, 파일명, 라인 번호, 함수명, 메시지 포함
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d - %(funcName)s() - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

def get_logger(name=None, level=logging.INFO):
    """
    지정된 이름으로 로거를 생성하고 반환.
    
    Args:
        name (str, optional): 로거 이름. 기본값은 None으로, 호출 모듈의 이름이 사용됩니다.
        level (int, optional): 로그 레벨. 기본값은 INFO.
        
    Returns:
        logging.Logger: 설정된 로거 인스턴스
    """
    # 로거 이름이 지정되지 않은 경우 호출 모듈의 이름을 사용
    if name is None:
        import inspect
        frame = inspect.stack()[1]
        module = inspect.getmodule(frame[0])
        name = module.__name__ if module else 'root'
    
    # 로거 생성
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False  # 루트 로거로 메시지 전파 방지
    
    # 이미 핸들러가 설정되어 있으면 추가 설정하지 않음
    if logger.handlers:
        return logger
    
    # 콘솔 핸들러 설정
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # 파일 핸들러 설정 (필요시 주석 해제)
    """
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=100*1024*1024,  # 100MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    """
    
    return logger

# 기본 로거 설정
def setup_root_logger(level=logging.INFO):
    """
    루트 로거를 설정.
    
    Args:
        level (int, optional): 로그 레벨. 기본값은 INFO.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # 기존 핸들러 제거
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # 콘솔 핸들러 설정
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # 파일 핸들러 설정 (필요시 주석 해제)
    """
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=100*1024*1024,  # 100MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    """

# 로그 레벨 문자열을 로깅 모듈 상수로 변환
def get_log_level(level_str):
    """
    문자열로 된 로그 레벨을 logging 모듈의 상수로 변환.
    
    Args:
        level_str (str): 로그 레벨 문자열 ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        
    Returns:
        int: logging 모듈의 로그 레벨 상수
    """
    levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    return levels.get(level_str.upper(), logging.INFO)