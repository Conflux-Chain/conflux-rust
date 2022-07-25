import multiprocessing as mp
import psutil

cpu_num = psutil.cpu_count(logical=False)


def pool():
    return mp.get_context("spawn").Pool(cpu_num)
