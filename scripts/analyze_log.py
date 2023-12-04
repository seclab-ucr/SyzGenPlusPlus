
import argparse
import os

from base import Command
from syzgen.target import Target

class AnalyzeLog(Command):

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-m", "--module", required=True,
                            help="target module")
        return super().init_parser(parser)

    def run(self, args, target: Target) -> None:
        wp = open(os.path.join("logs", f"{args.module}_simplified.txt"), "w")
        fp = open(os.path.join("logs", f"{args.module}.log"), "r")

        # total_time = 0
        pre_time, exec_time, post_time = [0, 0], [0, 0], [0, 0]
        dep_time = 0
        mode = 0
        for line in fp:
            line = line.strip()
            if "Start to extract commands" in line:
                mode = 0
            elif "start to analyze cmd" in line:
                mode = 1
            elif "pre_execute:" in line:
                pre_time[mode] += float(line.split()[-1][:-4])
            elif "post_execute: " in line:
                post_time[mode] += float(line.split()[-1][:-4])
                # print(post_time[mode], float(line.split()[-1][:-4]))
            elif "execute: " in line:
                exec_time[mode] += float(line.split()[-1][:-4])
            elif "infer dependency took" in line:
                dep_time += float(line.split()[-1][:-4])
            elif "[Verify Dependency fd] It took " in line:
                dep_time += float(line[line.index("took"):].split()[1])
            else:
                continue

            wp.write(line + "\n")

        wp.write(f"[Extract cmd] Total time is: {pre_time[0]}, {exec_time[0]}, {post_time[0]} = {pre_time[0] + exec_time[0] + post_time[0]}s\n")
        wp.write(f"[Infer Type] Total time is: {pre_time[1]}, {exec_time[1]}, {post_time[1]} = {pre_time[1] + exec_time[1] + post_time[1]}s\n")
        wp.write(f"[Verify Dependency] Total time is: {dep_time}s\n")
        wp.write("===================================\n")

        fp.close()
        wp.close()

if __name__ == '__main__':
    AnalyzeLog().start()
