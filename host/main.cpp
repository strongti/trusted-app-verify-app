
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
#include <fstream>
#include <unistd.h>
#include <sys/types.h>
#include "hello_world_ta.h"
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <vsomeip/vsomeip.hpp>

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include "hello_world_ta.h"
//
int main(void)
{
            TEEC_Result res;
            TEEC_Context ctx;
            TEEC_Session sess;
            TEEC_Operation op;
            TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
            uint32_t err_origin;
            res = TEEC_InitializeContext(NULL, &ctx);
	        if (res != TEEC_SUCCESS)
		        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
            res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	        if (res != TEEC_SUCCESS)
		    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			    res, err_origin);

            // 암호화된 데이터 파일 읽기
            std::ifstream file("encrypted_data.bin", std::ios::binary);
            std::vector<char> encrypted_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();        
                
            // TEEC_Operation 설정
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
            op.params[0].tmpref.buffer = encrypted_data.data();
            op.params[0].tmpref.size = encrypted_data.size();
            op.params[1].value.a = 15; // 예를 들어 socket fd 값

            // TA에 커맨드 전송
            res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CMD_INC_VALUE, &op, &err_origin);
            if (res != TEEC_SUCCESS) errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
            printf("Set Emergency\n");
            TEEC_CloseSession(&sess);

	    TEEC_FinalizeContext(&ctx);

	return 0;
}
