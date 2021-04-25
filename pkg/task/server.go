package task

import (
	"fs/pkg/logger"
	"fs/pkg/task/worker"
)

func Start() {
	// 1. 启动服务，连接 redis
	worker.StartServer()
	// 2. 启动异步调度
	taskWorker := worker.NewAsyncTaskWorker(10)
	err := taskWorker.Launch()
	if err != nil {
		logger.Errorf("启动 machinery 失败, %v", err.Error())
	}

}
