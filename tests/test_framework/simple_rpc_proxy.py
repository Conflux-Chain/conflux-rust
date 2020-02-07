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
                return_code = node.process.poll()
                # TODO Parameterize return_code
                if return_code == 100:
                    # TODO Handle extra_args
                    node.start(stdout=node.stdout, stderr=node.stderr)
                    node.wait_for_rpc_connection()
                    node.wait_for_nodeid()
                    node.wait_for_recovery("NormalSyncPhase", 30)
                    response = self.client.send(request, timeout=self.timeout)
                    return response.data.result
                else:
                    print(node.index, "exit with code", return_code)
                    raise e
            else:
                raise e
