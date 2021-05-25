package database

var (
	DbType   string
	Host     string
	Port     int
	Name     string
	Username string
	Password string
)

type Mysql struct {
}

func (e *Mysql) Setup() {

	var err error
	var db Database

}
