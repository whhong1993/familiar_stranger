package api

import (
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"fs/database"
	"fs/pkg/task"
	"fs/router"
	"fs/tools"
	config2 "fs/tools/config"
)

var (
	config   string
	port     string
	mode     string
	StartCmd = &cobra.Command{
		Use:     "server",
		Short:   "Start API server",
		Example: "octet server config/setting.yaml",
		PreRun: func(cmd *cobra.Command, args []string) {
			usage()
			setup()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run()
		}, 
	}
)

func init() {
	StartCmd.PersistentFlags().StringVarP(&config, "config", "c", "config/settings.yml", "Start server with provided configuration file")
	StartCmd.PersistentFlags().StringVarP(&port, "port", "p", "8002", "Tcp port server listening on")
	StartCmd.PersistentFlags().StringVarP(&mode, "mode", "m", "dev", "Server mode; eg: dev, test, prod")
}


func usage() {
	usageStr := `Starting api server`
	log.Printf("%s\n", usageStr)
}

func setup() {

	// 1. 读取配置
	config2.ConfigSetup(config)
	// 2. 初始化数据库
	database.Setup()
	// 3. 启动异步任务队列
	go task.Start()
}

func run() error {
	if mode != "" {
		config2.SetConfig(config, "settings.application.mode", mode)
	}
	if viper.GetString("settings.application.mode") == string(tools.ModeProd) {
		gin.SetMode(gin.ReleaseMode)
	}

	r := router.InitRouter()

}
