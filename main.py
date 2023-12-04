#! /usr/bin/python3

import argparse
import logging
import time

from syzgen.target import Target

import syzgen.config as Config

from syzgen.config import AnalysisType, Options, str2typenum


str2bool = lambda x: x not in {"False", "false"}
str2int = lambda x: int(x, 16) if x.startswith("0x") else int(x)

logger = logging.getLogger("syzgen")

def handle_find_drivers(target: Target, args):
    target.find_drivers(target=args.target)

def handle_find_cmd(target: Target, args):
    target.find_cmds(args.target)

def handle_infer_type(target: Target, args):
    target.infer_type(args.target, cmd=args.cmd, is_async=args.is_async, kcov=args.kcov)

def handle_do_all(target: Target, args):
    target.analyze(args.target)
    target.generate_template(
        args.target,
        True, # finalize
        True, # build
        options.getConfigKey("cover", False)
    )

def handle_show_model(target: Target, args):
    target.showcase(args.target, cmd=args.cmd)

def handle_gen_template(target: Target, args):
    target.generate_template(args.target, args.finalize, not args.nobuild, is_async=args.is_async)

def handle_gen_model(target: Target, args):
    target.generate_model(args.target, is_async=args.is_async)

ACTIONS = {
    AnalysisType.ALL: handle_do_all,
    AnalysisType.FIND_CMD: handle_find_cmd,
    AnalysisType.INFER_TYPE: handle_infer_type,
    AnalysisType.FIND_DRIVER: handle_find_drivers,

    AnalysisType.SHOW: handle_show_model,
    AnalysisType.GEN_TEMPLATE: handle_gen_template,
    AnalysisType.GEN_MODEL: handle_gen_model,
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="main")
    parser.add_argument('-t', '--test', default=False, action="store_true", help="for testing only")
    parser.add_argument('--config', default="config", help="path to the config file")
    parser.add_argument('--target', help="name of the interface (eg, class name or device file name)")
    parser.add_argument('--manual', default=False, action="store_true", help="manually launch debugger")
    parser.add_argument('--is_async', default=False, type=str2bool, help="do not need async methods")
    # parser.add_argument('--find_class', help="find class")
    parser.add_argument('--no_mem', default=False, action="store_true", help="do not inspect memory when analyzing dispatch table")
    parser.add_argument('--no_log', default=False, action="store_true", help="do no analyze logs")
    parser.add_argument('--finalize', default=True, type=str2bool, help="finalize specification")
    parser.add_argument('--nobuild', default=False, action="store_true", help="do not compile the template")
    parser.add_argument('--debug_file', default="", help="path to debug output file")
    parser.add_argument('--cmd', default=-1, type=str2int, help="specifiy which command to analyze")
    parser.add_argument('--kcov', nargs="*", help="cov json files")
    parser.add_argument('-s', '--step', default="all", type=str2typenum, choices=list(AnalysisType), help="run which analysis")
    parser.add_argument('--measure', default=False, action="store_true", help="record the time cost")

    options = Options()
    options.add_options(parser)

    args = parser.parse_args()
    options.set_options(args)
    Config.CONFIG_PATH = args.config

    if args.measure:
        name = args.debug_file or f"{args.target}.log"
        handler = logging.FileHandler(name, "a+")
        handler.setFormatter(logging.Formatter())
        logging.getLogger().addHandler(handler)
        logger.setLevel(logging.INFO)
    elif args.debug:
        name = args.debug_file or f"{args.target}.log"
        handler = logging.FileHandler(name, "w+")
        handler.setFormatter(logging.Formatter())
        logging.getLogger().addHandler(handler)
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.step.require_target():
        if not args.target:
            logger.error("empty target")
            exit(1)

    target = Target.Create()
    start_time = time.time()

    if args.step in ACTIONS:
        ACTIONS[args.step](target, args)
    else:
        parser.print_usage()

    logger.info("syzgen took %ds to finish", time.time() - start_time)
