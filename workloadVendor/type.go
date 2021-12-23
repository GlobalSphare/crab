package workloadVendor

import "time"

type WorkloadVendor struct {
	Id     int64  `gorm:"primaryKey" json:"id"`
	Name  string `json:"name"`
	Ver   string `json:"apiVersion" gorm:"column:ver"`
	Value string `json:"value"`

	Type int `json:"type"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (WorkloadVendor) TableName() string {
	return "t_vendor"
}

