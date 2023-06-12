package hospital

type Payment struct {
	PayID     int     `gorm:"column:pay_id;int;primaryKey;autoIncrement"	json:"pay_id"`
	PatientID int     `gorm:"column:patient_id;int"							json:"patient_id"`
	PayTotal  string  `gorm:"column:pay_total;varchar(255)"					json:"pay_total"`
	Patient   Patient `gorm:"foreignKey:PatientID"`
}

type PaymentInput struct {
	PatientID int    `json:"patient_id"`
	PayTotal  string `json:"pay_total"`
}

type PaymentResponse struct {
	PayID     int    			`json:"pay_id"`
	PatientID int    			`json:"patient_id"`
	PayTotal  string 			`json:"pay_total"`
}

type PaymentListResponse struct {
	Payments []PaymentResponse `json:"payments"`
}
