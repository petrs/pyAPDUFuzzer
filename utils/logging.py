import logging
from datetime import datetime
import os


def init_logging(log_level, log_path=""):
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(name)-15s %(levelname)-8s %(message)s',
                        datefmt='%d.%m.%Y %H:%M')

    logging.getLogger("llsmartcard.card").setLevel(logging.ERROR)
    logging.getLogger("fuzzer").setLevel(log_level)
    logging.getLogger("card.interactor").setLevel(logging.WARNING)

    if log_path != "":
        if not os.path.exists(log_path):
            os.makedirs(log_path)

        filename = "widen_{}.log".format(datetime.now().strftime("%Y%m%d_%H%M%S"))
        fh = logging.FileHandler("{}/{}".format(log_path, filename), 'w')
        fh.setLevel(log_level)

        formatter = logging.Formatter('%(asctime)s %(name)-15s %(levelname)-8s %(message)s')
        fh.setFormatter(formatter)
        logging.getLogger().addHandler(fh)


def _log(logger, message, level):
    logging.getLogger(logger).log(level, message)


def info(logger, message):
    _log(logger, message, logging.INFO)


def debug(logger, message):
    _log(logger, message, logging.DEBUG)


def warning(logger, message):
    _log(logger, message, logging.WARNING)


def error(logger, message):
    _log(logger, message, logging.ERROR)
