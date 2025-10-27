in_pipe = None


def set_pipe(pipe, ptype: int):
    '''
    ### Sets global module pipe
    `type`: int - `0` for input pipe, `1` - for output pipe
    '''
    global in_pipe
    global out_pipe
    if ptype == 1:
        out_pipe = pipe
    else:
        in_pipe = pipe


def get_pipe(ptype: int):
    '''
    ### Gets global module pipe
    `type`: int - `0` for input pipe, `1` - for output pipe
    '''
    return out_pipe if ptype == 1 else in_pipe
