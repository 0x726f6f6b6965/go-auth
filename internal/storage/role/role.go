package role

import (
	"github.com/0x726f6f6b6965/go-auth/internal/storage/models"
	"gorm.io/gorm"
)

type StorageRole struct {
	Table *models.Role
	db    *gorm.DB
}

func New(db *gorm.DB) StorageRole {
	return StorageRole{
		Table: &models.Role{},
		db:    db,
	}
}

func (m *StorageRole) GetRoleInfo(name string) (models.Role, error) {
	data := models.Role{
		RoleName: name,
	}
	err := m.db.First(&data).Error
	return data, err
}

func (m *StorageRole) DeleteRole(id int) error {
	err := m.db.Table(m.Table.TableName()).Delete("id = ?", id).Error
	return err
}
