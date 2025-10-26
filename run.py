import sys
import os
import logging
from os_ken.cmd.manager import main as osken_main


sys.path.insert(0, os.path.dirname(__file__))


def run_controller():
    sys.argv = [
        "osken-manager",
        "controller.app",
        "--verbose",
        "--observe-links",
    ]

    print("Starting Load Balancer Controller...")
    osken_main()


if __name__ == "__main__":
    logging.basicConfig(
        filename="controller.log",
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    run_controller()
