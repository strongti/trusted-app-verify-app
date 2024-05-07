/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <hello_world_ta.h>

// TEE_Result rsa_verify_signature_with_hash(uint8_t* signed_data, size_t signed_data_len,
//                                           uint8_t* modulus, size_t modulus_size,
//                                           uint8_t* exponent, size_t exponent_size,
//                                           uint8_t* message, size_t message_len);

TEE_Result verify_signature_with_public_key(uint8_t* signed_data, size_t signed_data_len,
                                            uint8_t* modulus, size_t modulus_size,
                                            uint8_t* exponent, size_t exponent_size,
                                            uint8_t* message, size_t message_len);
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}



// TEE_Result verify_signature_with_public_key(uint8_t* signed_data, size_t signed_data_len,
//                                             uint8_t* modulus, size_t modulus_size,
//                                             uint8_t* exponent, size_t exponent_size,
//                                             uint8_t* message, size_t message_len) {
//     TEE_Result res;
//     TEE_ObjectHandle rsa_key = TEE_HANDLE_NULL;
//     TEE_OperationHandle op = TEE_HANDLE_NULL;
//     TEE_OperationHandle hash_op = TEE_HANDLE_NULL;
//     uint8_t hash[1000] = {0}; // SHA-256 해시 버퍼
//     uint32_t hash_len = sizeof(hash); // 해시 길이 초기화

//     // 메시지 해시 계산
//     res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
//     if (res != TEE_SUCCESS) return res;

//     TEE_DigestUpdate(hash_op, message, message_len);
//     res = TEE_DigestDoFinal(hash_op, NULL, 0, hash, &hash_len);
//     TEE_FreeOperation(hash_op); // 해시 오퍼레이션 해제
//     if (res != TEE_SUCCESS) return res;

//     // 공개키 객체 생성
//     res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, 2048, &rsa_key);
//     if (res != TEE_SUCCESS) return res;

//     // 공개키 속성 설정
//     TEE_Attribute attrs[2];
//     TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, modulus, modulus_size);
//     TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, exponent, exponent_size);
//     res = TEE_PopulateTransientObject(rsa_key, attrs, 2);
//     if (res != TEE_SUCCESS) {
//         TEE_FreeTransientObject(rsa_key);
//         return res;
//     }

//     // 서명 검증 오퍼레이션 설정
//     res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5, TEE_MODE_VERIFY, 2048);
//     if (res != TEE_SUCCESS) {
//         TEE_FreeTransientObject(rsa_key);
//         return res;
//     }

//     res = TEE_SetOperationKey(op, rsa_key);
//     if (res != TEE_SUCCESS) {
//         TEE_FreeOperation(op);
//         TEE_FreeTransientObject(rsa_key);
//         return res;
//     }

//     // 서명 검증
//     res = TEE_AsymmetricVerifyDigest(op, NULL, 0, hash, hash_len, signed_data, signed_data_len);
//     TEE_FreeOperation(op);
//     TEE_FreeTransientObject(rsa_key);

//     return res;
// }


TEE_Result verify_signature_with_public_key(uint8_t* signed_data, size_t signed_data_len,
                                            uint8_t* modulus, size_t modulus_size,
                                            uint8_t* exponent, size_t exponent_size,
                                            uint8_t* message, size_t message_len) {
    TEE_Result res;
    TEE_ObjectHandle rsa_key = TEE_HANDLE_NULL;
    TEE_OperationHandle op = TEE_HANDLE_NULL;

    // 공개키 객체 생성
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, 2048, &rsa_key);
    if (res != TEE_SUCCESS) return res;

    // 공개키 속성 설정
    TEE_Attribute attrs[2];
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, modulus, modulus_size);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, exponent, exponent_size);
    res = TEE_PopulateTransientObject(rsa_key, attrs, 2);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(rsa_key);
        return res;
    }

    // 서명 검증 오퍼레이션 설정
    res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5, TEE_MODE_VERIFY, 2048);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(rsa_key);
        return res;
    }

    res = TEE_SetOperationKey(op, rsa_key);
    if (res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        TEE_FreeTransientObject(rsa_key);
        return res;
    }

    // 서명 검증 (메시지에 대한 내부 해시 계산이 자동으로 수행됨)
    res = TEE_AsymmetricVerifyDigest(op, NULL, 0, message, message_len, signed_data, signed_data_len);
    TEE_FreeOperation(op);
    TEE_FreeTransientObject(rsa_key);

    return res;
}

static TEE_Result inc_value(uint32_t param_types, TEE_Param params[4]) {
    // 예상되는 파라미터 타입 설정
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
											   TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_NONE);

    // 파라미터 타입 검사
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 공개키 모듈러스와 지수 추출
    uint8_t* modulus = (uint8_t*)params[2].memref.buffer;
    size_t modulus_size = 256; // RSA 2048-bit의 모듈러스 사이즈
    uint8_t* exponent = modulus + modulus_size; // 지수는 모듈러스 바로 이후에 위치
    size_t exponent_size = params[2].memref.size - modulus_size; // 지수 사이즈 계산

    // 서명 검증 호출
    uint8_t data[] = {0x31, 0x32, 0x33}; // 검증하려는 실제 데이터 "123"
    TEE_Result res = verify_signature_with_public_key(
        params[1].memref.buffer, params[1].memref.size,
        modulus, modulus_size,
        exponent, exponent_size,
        data, sizeof(data)
    );

    // 결과에 따른 처리 || res == TEE_ERROR_SIGNATURE_INVALID
    if (res == TEE_SUCCESS ) {
        params[0].value.a = 12; // 값 설정, 예제에서는 12로 설정하였으나, 실제 사용 사례에 따라 달라질 수 있음
        return TEE_SUCCESS;
    } else {
        return res; // 실패한 경우, 해당 오류를 반환
    }
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");
    params[0].value.a = 5555;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;


	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_HELLO_WORLD_CMD_INC_VALUE:
		return inc_value(param_types, params);
	case TA_HELLO_WORLD_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
