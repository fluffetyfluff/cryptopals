import hmac
import random
import time

import web

key = random.randbytes(16)

urls = ("/", "index", "/test", "test", "/faster", "faster")
app = web.application(urls, globals())


class index:
    def GET(self):
        return "hehe"


class test:
    def GET(self):
        input = web.input()
        file: str = input.file
        signature: str = input.signature

        real_sig = hmac.new(key, file.encode(), "sha1").hexdigest()
        for left, right in zip(signature, real_sig):
            time.sleep(0.05)
            if left != right:
                print(f"attempt : {signature}\nreal sig: {real_sig}")
                raise web.InternalError("bad signature")

        return f"file: {file}\nsignature: {signature}"


class faster:
    def GET(self):
        input = web.input()
        file: str = input.file
        signature: str = input.signature

        real_sig = hmac.new(key, file.encode(), "sha1").hexdigest()
        for left, right in zip(signature, real_sig):
            time.sleep(0.005)
            if left != right:
                raise web.InternalError("bad signature")

        return f"file: {file}\nsignature: {signature}"


if __name__ == "__main__":
    app.run()
