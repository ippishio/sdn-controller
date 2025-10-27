import uvicorn
import logging

from fastapi import FastAPI
from controller.api.rules import router as rules_router
from controller.api.pipe_manager import set_pipe


app = FastAPI()
app.include_router(rules_router)
logger = logging.getLogger(__name__)


def run_api(out_pipe, in_pipe):
    logger.debug(f"in_pipe : {in_pipe}")
    logger.debug(f"in_pipe : {out_pipe}")
    set_pipe(in_pipe, 0)
    set_pipe(out_pipe, 1)
    logger.info("REST API started on port 8080")
    uvicorn.run(app, host="0.0.0.0", port=8080)
    logger.info("REST API stops")
