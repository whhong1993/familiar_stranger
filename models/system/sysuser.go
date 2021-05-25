package system

type User struct {
	IdentityKey string

	UserName  string
	FirstName string
	LastName  string

	Role string
}

type UserName struct {
	Username string `gorm:"type:varchar(64)" json:"username"`
}

type PassWord struct {
	Password string `gorm:"type:varchar(128)" json:"password"`
}

type LoginM struct {
	UserName
	PassWord
}

type SysUserId struct {
	UserId int `gorm:"primary_key;AUTO_INCREMENT" json:"UserId"`
}
