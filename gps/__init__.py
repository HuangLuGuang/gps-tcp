import logging
import os
from logging.handlers import RotatingFileHandler

from .config import config_dict, CURRENT_ENV

conf = config_dict[CURRENT_ENV]


def setup_log(name):
    """配置日志"""

    # 设置日志的记录等级
    log_level = conf.LOG_LEVEL
    logging.basicConfig(level=log_level)
    # 日志目录
    log_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__))) + '/logs'
    if not os.path.exists(log_path):
        os.makedirs(log_path)
    # 创建日志记录器，指明日志保存的路径、每个日志文件的最大大小、保存的日志文件个数上限
    file_log_handler = RotatingFileHandler(
        "{log_path}/{name}".format(log_path=log_path, name=name))
    file_log_handler.setLevel(log_level)
    # 到控制台记录器
    console_log_handler = logging.StreamHandler()
    console_log_handler.setLevel(log_level)
    # 创建日志记录的格式 日志等级 输入日志信息的文件名 行数 日志信息
    formatter = logging.Formatter(
        '%(asctime)s--%(levelname)s %(filename)s:%(lineno)d %(message)s')
    # 为刚创建的日志记录器设置日志记录格式
    file_log_handler.setFormatter(formatter)
    # 为全局的日志工具对象（flask app使用的）添加日志记录器
    logger = logging.getLogger(name)
    logger.addHandler(file_log_handler)

    return logger
