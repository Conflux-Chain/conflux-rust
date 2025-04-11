from concurrent.futures import ThreadPoolExecutor
import threading
import queue
import subprocess
import os
import tomllib
import time

SPECIAL_SCRIPTS = {
    "ghast_consensus_test.py": 1
}

def get_num_test_nodes(py, test_dir, script):
    if script in SPECIAL_SCRIPTS:
        return SPECIAL_SCRIPTS[script]
    toml_output = subprocess.check_output(
        [py, os.path.join(test_dir, script), "--print-test-params"], text=True)
    toml_data = tomllib.loads(toml_output)
    return toml_data["num_nodes"]


class TestScheduler:
    """Scheduler for managing test execution and controlling concurrency based on resource requirements"""

    def __init__(self, task_executable, py, test_dir, max_workers, available_nodes, port_min, port_max, conflux_binary):
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

    def schedule(self, test_scripts):
        """Schedules the execution of test scripts"""
        
        # Prepare task queue
        task_queue = self._prepare_task_queue(test_scripts)
        
        # Execute tests using thread pool
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            self._process_task_queue(executor, task_queue)
            self._collect_results()
        return self.failed_tests

    def _prepare_task_queue(self, test_scripts):
        """Prepares a task queue with scripts and resource requirements"""
        
        task_queue = queue.Queue()
        print("Scanning num_nodes requirement for each task.", end = "")
        with ThreadPoolExecutor() as executor:
            tasks = [(executor.submit(
                      get_num_test_nodes, 
                      self.py, 
                      self.test_dir,
                      script), i, script) for i, script in enumerate(test_scripts)]
            
            # Collect completed task results and add them to the queue
            for future, i, script in tasks:
                result = future.result()
                task_queue.put((script, result, i))
        print(" Done")
        return task_queue

    def _process_task_queue(self, executor, task_queue):
        """Processes the task queue, scheduling tests based on resource availability"""
        
        while not task_queue.empty():
            try:
                # Retrieve task
                script, nodes_needed, index = task_queue.get(block=False)
                
                # Attempt to allocate resources
                if self._try_acquire_resources(nodes_needed):
                    # Enough resources available, execute test
                    future = executor.submit(
                        self._run_test_with_cleanup,
                        script,
                        index,
                        nodes_needed
                    )
                    self.results.append((script, future))
                    
                    # Wait for at least 1 second to avoid launch a lot of tasks
                    time.sleep(1)
                else:
                    # Insufficient resources, re-add to queue and wait
                    task_queue.put((script, nodes_needed, index))
                    self.resource_event.wait(timeout=0.2)
                    self.resource_event.clear()
            except queue.Empty:
                break

    def _try_acquire_resources(self, nodes_needed):
        """Attempts to acquire required resources, returns True if successful"""
        
        with self.resource_lock:
            if nodes_needed <= self.available_nodes and self.available_workers >= 1:
                self.available_nodes -= nodes_needed
                self.available_workers -= 1
                return True
            return False

    def _release_resources(self, nodes_count):
        """Releases resources and notifies waiting threads"""
        
        with self.resource_lock:
            self.available_nodes += nodes_count
            self.available_workers += 1
            self.resource_event.set()

    def _run_test_with_cleanup(self, script, index, nodes_count):
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
