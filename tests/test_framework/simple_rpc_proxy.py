import time

import jsonrpcclient.client
jsonrpcclient.client.request_log.propagate = False
jsonrpcclient.client.response_log.propagate = False


class SimpleRpcProxy:
    def __init__(self, url, timeout, node):
        self.url = url
        self.timeout = timeout
        self.node = node
        from jsonrpcclient.clients.http_client import HTTPClient
        self.client = HTTPClient(url)

    def __getattr__(self, name):
        return RpcCaller(self.client, name, self.timeout, self.node)


class RpcCaller:
    def __init__(self, client, method, timeout, node):
        self.client = client
        self.method = method
        self.timeout = timeout
        self.node = node

    def __call__(self, *args, **argsn):
        if argsn:
            raise ValueError('json rpc 2 only supports array arguments')
        from jsonrpcclient.requests import Request
        request = Request(self.method, *args)
        try:
            response = self.client.send(request, timeout=self.timeout)
            return response.data.result
        except Exception as e:
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
                    response = self.client.send(request, timeout=self.timeout)
                    return response.data.result
                else:
                    print(node.index, "exit with code", return_code, "during calling", self.method, "exception is", e)
                    raise e
            else:
                raise e
