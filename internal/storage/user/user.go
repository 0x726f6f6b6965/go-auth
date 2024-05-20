package user

import (
	"github.com/0x726f6f6b6965/go-auth/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type SotrageUsers struct {
	Table *models.User
	db    *gorm.DB
}

func New(db *gorm.DB) *SotrageUsers {
	return &SotrageUsers{
		Table: &models.User{},
		db:    db,
	}
}

func (m *SotrageUsers) GetUserInfo(email string) (*models.User, error) {
	data := models.User{}
	err := m.db.Table(m.Table.TableName()).Where("email = ?", email).First(&data).Error
	return &data, err
}

// GetUserInfoWithRoles get user info with roles
func (m *SotrageUsers) GetUserInfoWithRoles(email string) (*models.UserWithRoles, error) {
	data := &models.UserWithRoles{}
	err := m.db.Preload("Roles").First(data, "email = ?", email).Error
	return data, err
}

// InsertUserWithRoles insert user with roles
func (m *SotrageUsers) InsertUserWithRoles(data models.UserWithRoles) (models.UserWithRoles, error) {
	err := m.db.Create(&data).Error
	return data, err
}

func (m *SotrageUsers) UpdateUserRole(userId int, roles []int) error {
	data := models.UserRoleRelationship{}
	err := m.db.Table("r_user_role").Where("user_id = ? and role_id not in ?", userId, roles).Delete(&data).Error
	if err != nil {
		return err
	}
	res := []models.UserRoleRelationship{}
	for _, id := range roles {
		res = append(res, models.UserRoleRelationship{
			UserId: userId,
			RoleId: id,
		})
	}
	err = m.db.Table("r_user_role").Clauses(clause.OnConflict{DoNothing: true}).Create(res).Error
	return err
}

func (m *SotrageUsers) DeleteUser(id int) error {
	err := m.db.Table(m.Table.TableName()).Delete("id = ?", id).Error
	return err
}

func (m *SotrageUsers) UpdateUser(id int, fields map[string]interface{}) error {
	tx := m.db.Table(m.Table.TableName()).Where("id = ?", id).UpdateColumns(fields)
	err := tx.Error
	return err
}
