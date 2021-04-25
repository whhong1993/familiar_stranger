package cmd

import (
	"errors"
	"github.com/spf13/cobra"
	"fs/cmd/api"
	"fs/pkg/logger"
	"os"
)

var rootCmd = &cobra.Command{
	Use:           "octet",
	Short:         "-v",
	SilenceErrors: true,
	DisableAutoGenTag:true,
	Long:	`octet`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires at least one arg")
		}
		return nil
	},

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		usageStr := "欢迎使用 octet, 可以使用 -h 查看命令"
		logger.Infof("%s\n", usageStr)
	},
}

func Init() {
	rootCmd.AddCommand(api.StartCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}