from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import os

def verify_signature():
    # 공개키 로드
    with open("public_key.pem", "rb") as key_file:
        public_key = load_pem_public_key(
            key_file.read()
        )

    # 검증할 데이터
    data = "123".encode()

    # 파일에서 서명 로드
    with open("signature.bin", "rb") as sig_file:
        signature = sig_file.read()

    # 서명 검증 시도
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Verification successful: The signature is valid.")
    except Exception as e:
        print(f"Verification failed: {e}")

# 함수 실행
verify_signature()
