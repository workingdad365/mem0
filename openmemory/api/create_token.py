import argparse
import datetime
from pathlib import Path # 추가
from fastmcp.server.auth.providers.bearer import RSAKeyPair

# 키 파일 경로 정의 (스크립트와 같은 디렉토리에 저장)
PRIVATE_KEY_FILE = Path("private_key.pem")
PUBLIC_KEY_FILE = Path("public_key.pem")

def main():
    parser = argparse.ArgumentParser(
        description="Generate a JWT for FastMCP Bearer authentication using RSA keys.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--user-id",
        required=True,
        help="User ID (will be set as the JWT 'sub' claim, e.g., your username or unique ID)"
    )
    parser.add_argument(
        "--client-name",
        help="Client Name (optional, will be included as 'client_name' in additional_claims of the JWT)"
    )
    parser.add_argument(
        "--expires-days",
        type=int,
        default=30,
        help="Token expiration in days"
    )
    parser.add_argument(
        "--issuer",
        default="https://openmemory.io/auth",
        help="JWT 'iss' (issuer) claim. Should match the 'issuer' in BearerAuthProvider config on the server."
    )
    parser.add_argument(
        "--audience",
        default="openmemory-mcp-server",
        help="JWT 'aud' (audience) claim. Should match the 'audience' in BearerAuthProvider config on the server."
    )
    parser.add_argument(
        "--scopes",
        nargs='*',
        help="Space-separated list of OAuth scopes to include in the JWT (optional)"
    )

    args = parser.parse_args()

    key_pair_message = ""
    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists():
        try:
            private_key_pem = PRIVATE_KEY_FILE.read_text()
            public_key_pem = PUBLIC_KEY_FILE.read_text()
            key_pair = RSAKeyPair(private_key=private_key_pem, public_key=public_key_pem)
            key_pair_message = f"Using existing RSA key pair from {PRIVATE_KEY_FILE} and {PUBLIC_KEY_FILE}."
        except Exception as e:
            print(f"Error loading existing key files: {e}. Generating new keys.")
            key_pair = RSAKeyPair.generate()
            PRIVATE_KEY_FILE.write_text(key_pair.private_key.get_secret_value())
            PUBLIC_KEY_FILE.write_text(key_pair.public_key)
            key_pair_message = f"Generated and saved new RSA key pair to {PRIVATE_KEY_FILE} and {PUBLIC_KEY_FILE}."
    else:
        key_pair = RSAKeyPair.generate()
        PRIVATE_KEY_FILE.write_text(key_pair.private_key.get_secret_value())
        PUBLIC_KEY_FILE.write_text(key_pair.public_key)
        key_pair_message = f"Generated and saved new RSA key pair to {PRIVATE_KEY_FILE} and {PUBLIC_KEY_FILE}."


    expires_in_seconds = args.expires_days * 24 * 60 * 60
    
    additional_claims = {}
    if args.client_name:
        additional_claims["client_name"] = args.client_name

    token = key_pair.create_token(
        subject=args.user_id,
        issuer=args.issuer,
        audience=args.audience,
        scopes=args.scopes if args.scopes else None,
        expires_in_seconds=expires_in_seconds,
        additional_claims=additional_claims if additional_claims else None
    )

    print("\n" + "=" * 70)
    print("JWT Generation Details")
    print("=" * 70)
    print(f"\n{key_pair_message}")
    print("\nFor FastMCP server configuration (`BearerAuthProvider`), use the following PUBLIC KEY:")
    print("(This key is also saved in/read from public_key.pem)")
    print("-" * 70)
    print(key_pair.public_key)
    print("-" * 70)
    print("\nGenerated JWT (to be used in 'Authorization: Bearer <JWT>' header):")
    print("-" * 70)
    print(token)
    print("=" * 70)
    if "Generated and saved new RSA key pair" in key_pair_message:
        print("\nIMPORTANT: A new private key has been saved to private_key.pem.")
        print("Ensure this file is kept secure and backed up if this is a production key.")
        print("Add private_key.pem to your .gitignore file if it's not already.")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
