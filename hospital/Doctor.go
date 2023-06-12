package hospital

type Doctor struct {
	DoctorID        int    `gorm:"column:doctor_id;int;primaryKey;autoIncrement"	json:"doctor_id"`
	DoctorName   	string `gorm:"column:doctor_name;varchar(255)"					json:"doctor_name"`
	DoctorLicense 	string `gorm:"column:doctor_license;varchar(255)"				json:"doctor_license"`
}

type DoctorInput struct {
	DoctorName    string `json:"doctor_name"`
	DoctorLicense string `json:"doctor_license"`
}

type DoctorResponse struct {
	DoctorID        int    `json:"doctor_id"`
	DoctorName   	string `json:"doctor_name"`
	DoctorLicense 	string `json:"doctor_license"`
}

type DoctorListResponse struct {
	Doctors []DoctorResponse `json:"doctors"`
}
