package hospital

type Diagnose struct {
	DiagnoseID           int     `gorm:"column:diagnosis_id;int;primaryKey;autoIncrement"	json:"diagnosis_id"`
	PatientID            int     `gorm:"column:patient_id;int"								json:"patient_id"`
	DoctorID             int     `gorm:"column:doctor_id;int"								json:"doctor_id"`
	DiagnosisDate        string  `gorm:"column:diagnosis_date;varchar(255)"					json:"diagnosis_date"`
	DiagnosisDescription string  `gorm:"column:diagnosis_description;varchar(255)"			json:"diagnosis_description"`
	Patient              Patient `gorm:"foreignKey:PatientID"`
	Doctor               Doctor  `gorm:"foreignKey:DoctorID"`
}

type DiagnoseInput struct {
	PatientID            int    `json:"patient_id"`
	DoctorID             int    `json:"doctor_id"`
	DiagnosisDate        string `json:"diagnosis_date"`
	DiagnosisDescription string `json:"diagnosis_description"`
}

type DiagnoseResponse struct {
	DiagnosisID          int    			`json:"diagnosis_id"`
	PatientID            int    			`json:"patient_id"`
	DoctorID             int    			`json:"doctor_id"`
	DiagnosisDate        string 			`json:"diagnosis_date"`
	DiagnosisDescription string 			`json:"diagnosis_description"`
}

type DiagnoseListResponse struct {
	Diagnoses []DiagnoseResponse `json:"diagnoses"`
}
