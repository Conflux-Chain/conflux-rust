import requests
import jsonrpcclient.client
RPC_WAIT_TIMEOUT = 60


class SessionTimeoutFix(requests.Session):
    local_timeout = RPC_WAIT_TIMEOUT

    def request(self, *args, **kwargs):
        timeout = kwargs.pop('timeout', self.local_timeout)
        return super().request(*args, **kwargs, timeout=timeout)


requests.Session = SessionTimeoutFix
jsonrpcclient.client.request_log.propagate = False
jsonrpcclient.client.response_log.propagate = False


# TODO handle timeout better
class SimpleRpcProxy:
    def __init__(self, url, timeout):
        self.url = url
        SessionTimeoutFix.local_timeout = timeout
        from jsonrpcclient.clients.http_client import HTTPClient
        self.client = HTTPClient(url)

    def __getattr__(self, name):
        return RpcCaller(self.client, name)


class RpcCaller:
    def __init__(self, client, method):
        self.client = client
        self.method = method

    def __call__(self, *args, **argsn):
        if argsn:
            raise ValueError('json rpc 2 only supports array arguments')
        response = self.client.request(self.method, *args)
        return response.data.result
