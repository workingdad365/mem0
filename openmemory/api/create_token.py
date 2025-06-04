import sys
import uuid
import argparse
import secrets
import datetime
from sqlalchemy.orm import sessionmaker
from app.database import SessionLocal
from app.models import User, UserToken

def generate_api_key():
    return secrets.token_urlsafe(32)

def main():
    parser = argparse.ArgumentParser(description="Create an API key (OPENMEMORY-API-KEY) for a given user_id.")
    parser.add_argument("--user-id", required=True, help="User ID (users.user_id)")
    parser.add_argument("--description", required=False, help="Description for this key (optional)")
    parser.add_argument("--expires-days", type=int, default=None, help="Days until key expires (optional)")
    parser.add_argument("--admin", action="store_true", help="Mark this key as admin (description will be set to 'admin' if not specified)")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_id == args.user_id).first()
        if not user:
            print(f"User not found: {args.user_id}")
            sys.exit(1)
        # 하나의 유효한 키만 허용 (기존 키 비활성화)
        db.query(UserToken).filter(UserToken.user_id == user.id, UserToken.is_active == True).update({UserToken.is_active: False})
        api_key = generate_api_key()
        expires_at = None
        if args.expires_days:
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=args.expires_days)
        description = args.description
        if args.admin and not description:
            description = "admin"
        token = UserToken(
            user_id=user.id,
            token=api_key,
            description=description,
            is_active=True,
            expires_at=expires_at
        )
        db.add(token)
        db.commit()
        print(f"UserToken created for user_id={args.user_id}")
        if args.admin:
            print("[ADMIN KEY]")
        print(f"OPENMEMORY-API-KEY: {api_key}")
    finally:
        db.close()

if __name__ == "__main__":
    main()
