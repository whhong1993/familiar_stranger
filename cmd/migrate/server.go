package migrate

import (
	"fmt"
	"fs/database"
	"fs/golbal/orm"
	config2 "fs/tools/config"
	"github.com/spf13/cobra"
)

var (
	config   string
	mode     string
	StartCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize the database",
		Run: func(cmd *cobra.Command, args []string) {
			run()
		},
	}
)

func init() {
	StartCmd.PersistentFlags().StringVarP(&config, "config", "c", "config/settings.yml", "Start server with provided configuration file")
	StartCmd.PersistentFlags().StringVarP(&mode, "mode", "m", "dev", "Server mode; eg:dev, test, prod")
}

func run() {
	usage := `start init`
	fmt.Println(usage)

	//1. 读取配置
	config2.Setup(config)
	//2. 初始化数据库连接
	database.Setup()
	//3. 数据库迁移
	_ = migrateModel()

}

func migrateModel() error {
	if config2.DatabaseConfig.Dbtype == "mysql" {
		orm.Eloquent = orm.Eloquent.Set("gorm:table_options", "ENGINE=InnoDB CHARSET=utf8mb4")
	}
	return gorm.Au
}
