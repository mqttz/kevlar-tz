#include <tee_client_api.h>
#include <err.h>

#include <mqttz_ta.h>

void prepare_tee_session(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_UUID uuid = TA_MQTTZ_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(ctx, sess, &uuid,
			               TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		        res, origin);
}

void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_CloseSession(sess);
	TEEC_FinalizeContext(ctx);
}

int main(void)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	prepare_tee_session(&ctx, &sess);
	res = TEEC_InvokeCommand(&sess, TA_MQTTZ, NULL, &origin);
	terminate_tee_session(&ctx, &sess);

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		        res, origin);

	return 0;
}
