
.PHONY: generate clean

generate:
	mkdir -p generated
	cat call_qcsapi_rpc.x > generated/call_qcsapi_rpc.x
	cd generated && rpcgen -M call_qcsapi_rpc.x
	cd generated && rpcgen -M -m call_qcsapi_rpc.x > call_qcsapi_rpc_svc.c

clean:
	rm -rf generated/

