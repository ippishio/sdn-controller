from controller.api.pipe_manager import get_pipe
from time import time
from fastapi import HTTPException


class ControllerAdapter:
    def __init__(self):
        self.out_pipe = None
        self.in_pipe = None

    def _lazy_init(self):
        if self.in_pipe is None:
            self.in_pipe = get_pipe(0)
        if self.out_pipe is None:
            self.out_pipe = get_pipe(1)

    def _wait_for_return_code(self, timeout: int = 5):
        # start_ts = time()
        resp = None
        if self.in_pipe.poll(timeout):
            resp = self.in_pipe.recv()
        # while resp is None and time() - start_ts < timeout:
        #     resp = self.in_pipe.recv()
        if resp is None:
            raise HTTPException(
                status_code=408,
                detail=f"Controller didn't answered in {timeout} seconds",
            )
        if resp["rc"] != 0:
            raise HTTPException(status_code=500, detail=resp["details"])

    def __getattr__(self, name):
        self._lazy_init()

        def method(*args, **kwargs):
            req = {"method": name, "args": args, "kwargs": kwargs}
            self.out_pipe.send(req)
            self._wait_for_return_code()

        return method


controller = ControllerAdapter()
