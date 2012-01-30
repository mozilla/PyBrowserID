# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import threading
import multiprocessing

from vep.verifiers.local import LocalVerifier


class WorkerPoolVerifier(object):
    """Class for verifying against a pool of worker processes.

    This class is a drop-in replacement for LocalVerifier that uses a pool
    of worker processes to side-step the GIL.  It can be very helpful on
    systems with lots of cores.

    By default a WorkerPoolVerifier will spawn as many processes as you
    have cpus on your system, and will check assertions against an instance
    of LocalVerifier.  You can customize this with the arguments "num_procs"
    and "verifier" respectively.
    """

    def __init__(self, num_procs=None, verifier=None):
        # Try to choose a sensible number of processes by default.
        if num_procs is None:
            try:
                num_procs = multiprocessing.cpu_count()
            except NotImplementedError:
                num_procs = 2
        # Use LocalVerifier by default, but allow overriding.
        if verifier is None:
            verifier = LocalVerifier()
        self.num_procs = num_procs
        self.verifier = verifier
        # Create the various communication channels.
        # Yes, this duplicates a lot of the logic from multprocessing.Pool.
        # I don't want to have to constantly pickle the verifier object
        # to send it into the subprocesses, and the Pool class doesn't lend
        # itself to subclases in a way that would avoid this.  So here we are.
        # We have:
        # 1) a queue from which the workers read jobs
        self._work_queue = multiprocessing.Queue()
        # 2) a queue into which the workers push results
        self._result_queue = multiprocessing.Queue()
        # 3) a thread that dispatches results to other waiting threads,
        #    by signalling on a condition object.
        self._lock = threading.Lock()
        self._waiting_conds = {}
        self._spare_conds = []
        # Now we can start the required processes and threads.
        self._result_thread = threading.Thread(target=self._run_result_thread)
        self._result_thread.start()
        self._processes = []
        for n in xrange(num_procs):
            proc = multiprocessing.Process(target=self._run_worker)
            self._processes.append(proc)
            proc.start()

    def __del__(self):
        self.close()

    def verify(self, *args, **kwds):
        """Verify the given VEP assertion.

        This method parses a VEP identity assertion, verifies the bundled
        chain of certificates and signatures, and returns the extracted
        email address and audience.

        If the 'audience' argument is given, it first verifies that the
        audience of the assertion matches the one given.  This can help
        avoid doing lots of crypto for assertions that can't be valid.
        If you don't specify an audience, you *MUST* validate the audience
        value returned by this method.

        Any other positional or keyword arguments will be passed on to the
        underlying verifier object.
        """
        with self._lock:
            # Get a condition with which to wait for the result.
            try:
                cond = self._spare_conds.pop()
            except IndexError:
                cond = threading.Condition(self._lock)
            job_id = id(cond)
            self._waiting_conds[job_id] = cond
            # Send the job to the workers, wait for the result.
            self._work_queue.put((job_id, args, kwds))
            cond.wait()
            ok, result = self._waiting_conds.pop(job_id)
            # Store the condition for reuse.
            self._spare_conds.append(cond)
            if ok:
                return result
            else:
                raise result

    def close(self):
        """Close down the worker processes.

        This method shuts down the various background processes and threads
        that are uses by the WorkerPoolVerifier.  It's good hygiene to call
        this explicitly, but it will be called by the destructor if you forget.
        """
        with self._lock:
            if self._work_queue is None:
                return
            for x in xrange(self.num_procs):
                self._work_queue.put((None, None, None))
            for proc in self._processes:
                proc.join()
            self._result_queue.put((None, None, None))
            self._result_thread.join()
            self._work_queue = None

    def _run_result_thread(self):
        """Method to run for the background result-dispatching thread.

        This method loops through results that are returned by the workers,
        dispatching them to the appropraite waiting thread.
        """
        while True:
            job_id, ok, result = self._result_queue.get()
            if job_id is None:
                break
            with self._lock:
                cond = self._waiting_conds[job_id]
                self._waiting_conds[job_id] = (ok, result)
                cond.notify()

    def _run_worker(self):
        """Method to run for the background worker processes.

        This method loops through jobs from the work queue, executing them
        with the verifier object and pushing the result back via the result
        queue.
        """
        while True:
            job_id, args, kwds = self._work_queue.get()
            if job_id is None:
                break
            try:
                result = self.verifier.verify(*args, **kwds)
                ok = True
            except Exception, e:
                result = e
                ok = False
            self._result_queue.put((job_id, ok, result))
