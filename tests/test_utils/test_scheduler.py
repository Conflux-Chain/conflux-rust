from concurrent.futures import ThreadPoolExecutor
import threading
import queue
import subprocess
import os
import tomllib
import time
from typing import Callable

SPECIAL_SCRIPTS = {
    "ghast_consensus_test.py": 1
}

def get_num_test_nodes(py: str, test_dir: str, script: str) -> int:
    if script in SPECIAL_SCRIPTS:
        return SPECIAL_SCRIPTS[script]
    toml_output = subprocess.check_output(
        [py, os.path.join(test_dir, script), "--print-test-params"], text=True)
    toml_data = tomllib.loads(toml_output)
    return toml_data["num_nodes"]


class TestScheduler:
    """Scheduler for managing test execution and controlling concurrency based on resource requirements"""

    def __init__(self,
                 task_executable: Callable[[str, str, str, int, int, int, str], None],
                 py: str,
                 test_dir: str,
                 max_workers: int,
                 available_nodes: int,
                 port_min: int,
                 port_max: int,
                 conflux_binary: str):
        self.task_executable = task_executable
        self.py = py
        self.test_dir = test_dir
        self.port_min = port_min
        self.port_max = port_max
        self.max_workers = max_workers
        self.conflux_binary = conflux_binary
        
        # Resource management
        self.available_nodes = available_nodes
        self.available_workers = max_workers
        self.resource_lock = threading.Lock()
        self.resource_event = threading.Event()
        
        # Result collection
        self.results = []
        self.failed_tests = set()

    def schedule(self, test_scripts: list[str]) -> set[str]:
        """Schedules the execution of test scripts"""
        
        # Prepare task queue
        task_queue = self._prepare_task_queue(test_scripts)
        
        # Execute tests using thread pool
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            self._process_task_queue(executor, task_queue)
            self._collect_results()
        return self.failed_tests

    def _prepare_task_queue(self, test_scripts: list[str]) -> list[tuple[str, int, int]]:
        """Prepares a task queue with scripts and resource requirements"""
        
        task_queue = []
        print("Scanning num_nodes requirement for each task")
        with ThreadPoolExecutor() as executor:
            tasks = [(executor.submit(
                      get_num_test_nodes, 
                      self.py, 
                      self.test_dir,
                      script), i, script) for i, script in enumerate(test_scripts)]
            
            # Collect completed task results and add them to the queue
            for future, i, script in tasks:
                result = future.result()
                if result > self.available_nodes:
                    raise RuntimeError(f"Cannot run {script} because it requires {result} nodes, "
                                       f"but only max to {self.available_nodes} nodes are available"
                                       f"Please specify --max-nodes to run the test")

                task_queue.append((script, result, i))
        task_queue.sort(key=lambda x: x[1], reverse=True)
        for script, nodes_needed, index in task_queue:
            print(f"Task {index}: {script} requires {nodes_needed} nodes")
        print("Scanning done")
        return task_queue
    
    def _pop_next_task(self, task_queue: list[tuple[str, int, int]]) -> tuple[str, int, int]:
        """Selects the next task to process"""
        if not task_queue:
            raise RuntimeError("No tasks to process")
        while True:
            for i, (script, nodes_needed, index) in enumerate(task_queue):
                if self._try_acquire_resources(nodes_needed):
                    task_queue.pop(i)
                    return script, nodes_needed, index
            self.resource_event.wait(timeout=10)
            self.resource_event.clear()

    def _process_task_queue(self, executor: ThreadPoolExecutor, task_queue: list[tuple[str, int, int]]):
        """Processes the task queue, scheduling tests based on resource availability"""
        
        while task_queue:
            script, nodes_needed, index = self._pop_next_task(task_queue)
            future = executor.submit(
                self._run_test_with_cleanup,
                script,
                index,
                nodes_needed
            )
            self.results.append((script, future))

    def _try_acquire_resources(self, nodes_needed: int) -> bool:
        """Attempts to acquire required resources, returns True if successful"""
        
        with self.resource_lock:
            if nodes_needed <= self.available_nodes and self.available_workers >= 1:
                self.available_nodes -= nodes_needed
                self.available_workers -= 1
                return True
            return False

    def _release_resources(self, nodes_count: int):
        """Releases resources and notifies waiting threads"""
        
        with self.resource_lock:
            self.available_nodes += nodes_count
            self.available_workers += 1
            self.resource_event.set()

    def _run_test_with_cleanup(self, script: str, index: int, nodes_count: int):
        """Runs a test and ensures resources are released"""
        
        try:
            return self.task_executable(
                self.py,
                script,
                self.test_dir,
                index,
                self.port_min,
                self.port_max,
                self.conflux_binary,
            )
        finally:
            self._release_resources(nodes_count)

    def _collect_results(self):
        """Collects and processes test results"""
        
        for script, future in self.results:
            try:
                future.result()
            except subprocess.CalledProcessError:
                self.failed_tests.add(script)
