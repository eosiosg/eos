//
// Created by Yu Yang Zhang on 8/31/19.
//

#ifndef EOSIO_THREADPOOL_HPP
#define EOSIO_THREADPOOL_HPP

#include <thread>
#include <memory>
#include <list>
#include <iostream>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <boost/thread/thread.hpp>
#include <boost/function.hpp>
#include <deque>
using namespace std;

namespace eosio{

typedef boost::function<void()> task_type;

class thread_wrapper {
private:
	unique_ptr<std::thread> thread;
	std::condition_variable cv_wait_task;
	std::mutex mutex_cv_wait_task;
	bool task_ready = false;
	bool finish = false;
	bool stop = false;
	std::mutex mutex_stop;
	std::condition_variable cv_wait_finish;
	std::mutex mutex_cv_wait_finish;
	deque<task_type> task_queue;
	std::mutex mutex_task_queue;

	void thread_function(){
		bool s;
		{
			std::lock_guard<std::mutex> lg(mutex_stop);
			s = stop;
		}
		while(!s) {
			{
				std::unique_lock<std::mutex> lock(mutex_cv_wait_task);
				cv_wait_task.wait(lock, [this] { return task_ready; });
				{
					std::lock_guard<std::mutex> lg(mutex_stop);
					s = stop;
				}
				if(s) break;
				task_ready = false;
			}
			std::unique_lock<std::mutex> lock_queue(mutex_task_queue);
			while (!task_queue.empty()) {
				auto task = task_queue.front();
				try {
					task();
				} catch (boost::bad_function_call &ex) {
					elog("call to empty boost function ${err}", ("err", ex.what()));
				}
				task_queue.pop_front();
			}
			lock_queue.unlock();
			{
				/// for sync operation to wait the sub thread task finish
				std::unique_lock<std::mutex> lock(mutex_cv_wait_finish);
				finish = true;
				cv_wait_finish.notify_one();
			}
		}
	}
public:
	thread_wrapper() {
		thread = make_unique<std::thread>(&thread_wrapper::thread_function, this);
	}

	void push_task(const task_type &f) {
		std::lock_guard<std::mutex> lock(mutex_task_queue);
		task_queue.emplace_back(f);
	}

	void run() {
		std::unique_lock<std::mutex> lock(mutex_cv_wait_task);
		task_ready = true;
		cv_wait_task.notify_one();
	}
	void wait() {
		std::unique_lock<std::mutex> lock(mutex_cv_wait_finish);
		cv_wait_finish.wait(lock, [this]{return finish;});
		finish = false;
	}

	~thread_wrapper() {
		{
			std::lock_guard<std::mutex> lg(mutex_stop);
			stop = true;
		}
		{
			std::unique_lock<std::mutex> lock(mutex_cv_wait_task);
			task_ready = true;
			cv_wait_task.notify_one();
		}
		thread->join();
	}
};



class thread_pool {
private:
	std::list<unique_ptr<thread_wrapper>> threads;
	std::mutex mutex;
public:
	thread_pool(int n){
		for(auto i = 0; i < n; i++){
			threads.emplace_back(make_unique<thread_wrapper>());
		}
	}
	~thread_pool() {
		while(not threads.empty()){
			threads.pop_front();
		}
	}
	unique_ptr<thread_wrapper> get_thread() {
		std::lock_guard<std::mutex> lg(mutex);
		if(!threads.empty()) {
			auto p =  std::move( threads.front());
			threads.pop_front();
			return p;
		}
		return nullptr;
	}

	void return_thread(unique_ptr<thread_wrapper>&& tw) {
		std::lock_guard<std::mutex> lg(mutex);
		threads.emplace_back(std::move(tw));
	}
};
}

#endif //EOSIO_THREADPOOL_HPP
