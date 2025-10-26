from controller.api.pipe_manager import get_pipe


class ControllerAdapter:
    def __init__(self):
        self.pipe = None

    def _lazy_init(self):
        if self.pipe is None:
            self.pipe = get_pipe()

    def __getattr__(self, name):
        self._lazy_init()

        def method(*args, **kwargs):
            req = {"method": name, "args": args, "kwargs": kwargs}
            self.pipe.send(req)

        return method


controller = ControllerAdapter()
