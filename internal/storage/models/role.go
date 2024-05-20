package models

import "time"

type Role struct {
	Id         int       `gorm:"column:id;type:integer;primary_key" json:"id"`
	RoleName   string    `gorm:"column:role_name;type:varchar(255);not null" json:"role_name"`
	CreateTime time.Time `gorm:"column:create_time;type:datetime;default:CURRENT_TIMESTAMP;NOT NULL" json:"create_time"`
	UpdateTime time.Time `gorm:"column:update_time;type:datetime;default:CURRENT_TIMESTAMP;NOT NULL" json:"update_time"`
}

func (m *Role) TableName() string {
	return "t_role"
}
