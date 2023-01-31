/*
 * Remote invocation of call_qcsapi
 */


typedef string str<>;

struct call_qcsapi_rpc_request {
	str argv<>;
};

struct call_qcsapi_rpc_result {
	int return_code;
	str stdout_produced;
	str stderr_produced;
};

program CALL_QCSAPI_PROG {
	version CALL_QCSAPI_VERS {
		call_qcsapi_rpc_result
		CALL_QCSAPI_REMOTE(struct call_qcsapi_rpc_request) = 1;
	} = 1;
} = 0x20000001;

