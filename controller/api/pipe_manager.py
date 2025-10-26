in_pipe = None


def set_pipe(pipe):
    global in_pipe
    in_pipe = pipe


def get_pipe():
    return in_pipe
