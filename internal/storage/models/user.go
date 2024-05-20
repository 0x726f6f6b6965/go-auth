package models

import (
	"time"
)

type User struct {
	Id         int       `gorm:"column:id;type:integer;primary_key" json:"id"`
	Username   string    `gorm:"column:username;type:varchar(128);not null" json:"username"`
	Password   string    `gorm:"column:password;type:varchar(128);not null" json:"password"`
	Salt       string    `gorm:"column:salt;type:varchar(64);not null" json:"salt"`
	Email      string    `gorm:"column:email;type:text;not null" json:"email"`
	Validate   bool      `gorm:"column:validate;type:boolean;default:false;not null" json:"validate"`
	CreateTime time.Time `gorm:"column:create_time;type:datetime;default:CURRENT_TIMESTAMP;NOT NULL" json:"create_time"`
	UpdateTime time.Time `gorm:"column:update_time;type:datetime;default:CURRENT_TIMESTAMP;NOT NULL" json:"update_time"`
}

type UserWithRoles struct {
	User
	Roles []Role `gorm:"many2many:r_user_role;foreignKey:id;joinForeignKey:user_id;References:id;joinReferences:role_id"`
}

type UserRoleRelationship struct {
	UserId int `gorm:"column:user_id;type:integer" json:"user_id"`
	RoleId int `gorm:"column:role_id;type:integer" json:"role_id"`
}

func (m *User) TableName() string {
	return "t_user"
}
