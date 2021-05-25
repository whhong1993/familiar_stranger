package config

import (
	"fmt"
	"fs/pkg/logger"
	"github.com/spf13/viper"
	"io/ioutil"
	"os"
	"strings"
)

var cfgDatabase *viper.Viper
var cfgApplication *viper.Viper
var cfgJwt *viper.Viper
var cfgSsl *viper.Viper

// 载入配置文件
func Setup(path string) {
	viper.SetConfigFile(path)
	content, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Fatal(fmt.Sprintf("Read config file fail: %s", err.Error()))
	}

	err = viper.ReadConfig(strings.NewReader(os.ExpandEnv(string(content))))
	if err != nil {
		logger.Fatal(fmt.Sprintf("Parse config file fail: %s", err.Error()))
	}

	// 数据库初始化
	cfgDatabase = viper.Sub("settings.database")
	if cfgDatabase == nil {
		panic("config not found settings.database")
	}
	DatabaseConfig = InitDatabase(cfgDatabase)

	// 启动参数
	cfgApplication = viper.Sub("settings.application")
	if cfgApplication == nil {
		panic("config not found settings.application")
	}
	ApplicationConfig = InitApplication(cfgApplication)

	//Jwt 初始化
	cfgJwt = viper.Sub("settings.jwt")
	if cfgJwt == nil {
		panic("config not found settings.jwt")
	}
	JwtConfig = InitJwt(cfgJwt)

	// ssl 配置
	cfgSsl = viper.Sub("settings.ssl")
	if cfgSsl == nil {
		panic("config not found settings.ssl")
	}
	SslConfig = InitSsl(cfgSsl)

	logger.Init()
}

func SetConfig(configPath string, key string, value interface{}) {
	viper.AddConfigPath(configPath)
	viper.Set(key, value)
	_ = viper.WatchConfig
}
