import time
from typing import Any

from jsonrpcclient import request, Error, Ok, parse
from requests import Session

class ReceivedErrorResponseError(Exception):
    def __init__(self, error: Error):
        self.response = error
    
    def __str__(self):
        return f"JSONRPCError(code={self.response.code}, message={self.response.message}, data={self.response.data})"


class SimpleRpcProxy:
    def __init__(self, url, timeout, node):
        self.url = url
        self.timeout = timeout
        self.node = node
        self.session = Session()

    def __getattr__(self, name):
        return RpcCaller(self.session, self.url, name, self.timeout, self.node)


class RpcCaller:
    def __init__(self, session: Session, url: str, method: str, timeout: int, node: Any):
        self.session = session
        self.url = url
        self.method = method
        self.timeout = timeout
        self.node = node

    def __call__(self, *args, **argsn) -> Any:
        if argsn:
            raise ValueError('json rpc 2 only supports array arguments')
        
        try:
            response = self.session.post(
                url=self.url,
                json=request(self.method, params=args),
                timeout=self.timeout
            )
            
            parsed = parse(response.json())
            if isinstance(parsed, Ok):
                return parsed.result
            else:
                raise ReceivedErrorResponseError(parsed)  # type: ignore
        except ReceivedErrorResponseError as e:
            node = self.node
            if node is not None and node.auto_recovery:
                # wait to ensure that the process has completely exited
                retry = 10
                return_code = None
                while return_code is None and retry > 0:
                    return_code = node.process.poll()
                    time.sleep(0.5)
                    retry -= 1
                # TODO Parameterize return_code
                # -11 means segfault, which may be triggered if rocksdb is not properly dropped.
                # 100 is our random db crash exit code.
                if return_code in [-11, 100]:
                    print(node.index, "recover from exit code", return_code, "during calling",
                          self.method, "exception is", e)
                    # TODO Handle extra_args
                    node.start(stdout=node.stdout, stderr=node.stderr)
                    node.wait_for_rpc_connection()
                    node.wait_for_nodeid()
                    node.wait_for_recovery("NormalSyncPhase", node.recovery_timeout)
                    response = self.session.post(
                        url=self.url,
                        json=request(self.method, params=args),
                        timeout=self.timeout
                    )
                    parsed = parse(response.json())
                    if isinstance(parsed, Ok):
                        return parsed.result
                    else:
                        raise ReceivedErrorResponseError(parsed)
                else:
                    print(node.index, "exit with code", return_code, "during calling", self.method, "exception is", e)
                    raise e
            else:
                print(f"rpc exception method {self.method} code {e.response.code}, message: {e.response.message}, data: {e.response.data}")
                raise e
