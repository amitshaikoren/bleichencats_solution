import multiprocessing as mp


def run_query_processes(oracles, queries, queue):
    query_processes = []

    for index in range(len(queries)):
        query_processes.append(QueryProcess(oracles[index], queries[index], index, queue))

    for query_process in query_processes:
        query_process.start()

    for query_process in query_processes:
        query_process.join()

def get_min_index_query(queue, num_of_queries):

    min_index = num_of_queries

    while not queue.empty():
        index = queue.get()
        if index < min_index:
            min_index = index

    return min_index

def query(oracles, queries):
    queue = mp.Queue()
    run_query_processes(oracles, queries, queue)

    return get_min_index_query(queue, len(queries))


class QueryProcess(mp.Process):

    def __init__(self, oracle, qinput, index, queue):
        mp.Process.__init__(self)
        self.oracle = oracle
        self.qinput = qinput
        self.index = index
        self.queue = queue

    def run(self):
        try:
            if self.oracle.query(self.qinput):
                self.queue.put(self.index)
        except Exception as ex:
            print(self.index, " : query failed")
            raise ex
