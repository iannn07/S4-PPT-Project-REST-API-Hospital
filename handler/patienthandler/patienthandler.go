package patienthandler

import (
	"net/http"
	"HospitalFinpro/hospital"
	"github.com/gin-gonic/gin"
)

func SelectAll(c *gin.Context) {
	var patients []hospital.Patient
	hospital.DB.Find(&patients)

	var patientResponses []hospital.PatientResponse
	for _, patient := range patients {
		patientResponse := hospital.PatientResponse{
			PatientID:     patient.PatientID,
			DoctorID:      patient.DoctorID,
			PatientName:   patient.PatientName,
			PatientDOB:    patient.PatientDOB,
			PatientGender: patient.PatientGender,
		}
		patientResponses = append(patientResponses, patientResponse)
	}

	c.JSON(http.StatusOK, gin.H{"data": patientResponses})
}

func Create(c *gin.Context) {
	var patientInput hospital.PatientInput
	if err := c.ShouldBindJSON(&patientInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	patient := hospital.Patient{
		PatientName:   patientInput.PatientName,
		PatientDOB:    patientInput.PatientDOB,
		PatientGender: patientInput.PatientGender,
		DoctorID:      patientInput.DoctorID,
	}

	if err := hospital.DB.Create(&patient).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create patient"})
		return
	}

	patientResponse := hospital.PatientResponse{
		PatientID:     patient.PatientID,
		DoctorID:      patient.DoctorID,
		PatientName:   patient.PatientName,
		PatientDOB:    patient.PatientDOB,
		PatientGender: patient.PatientGender,
	}

	c.JSON(http.StatusOK, gin.H{"data": patientResponse})
}

func Read(c *gin.Context) {
	var patient hospital.Patient
	if err := hospital.DB.Where("patient_id = ?", c.Param("id")).First(&patient).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	patientResponse := hospital.PatientResponse{
		PatientID:     patient.PatientID,
		DoctorID:      patient.DoctorID,
		PatientName:   patient.PatientName,
		PatientDOB:    patient.PatientDOB,
		PatientGender: patient.PatientGender,
	}

	c.JSON(http.StatusOK, gin.H{"data": patientResponse})
}

func Update(c *gin.Context) {
	var patient hospital.Patient
	if err := hospital.DB.Where("patient_id = ?", c.Param("id")).First(&patient).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	var patientInput hospital.PatientInput
	if err := c.ShouldBindJSON(&patientInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	patient.PatientName = patientInput.PatientName
	patient.PatientDOB = patientInput.PatientDOB
	patient.PatientGender = patientInput.PatientGender
	patient.DoctorID = patientInput.DoctorID

	if err := hospital.DB.Save(&patient).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update patient"})
		return
	}

	patientResponse := hospital.PatientResponse{
		PatientID:     patient.PatientID,
		DoctorID:      patient.DoctorID,
		PatientName:   patient.PatientName,
		PatientDOB:    patient.PatientDOB,
		PatientGender: patient.PatientGender,
	}

	c.JSON(http.StatusOK, gin.H{"data": patientResponse})
}

func Delete(c *gin.Context) {
	var patient hospital.Patient
	if err := hospital.DB.Where("patient_id = ?", c.Param("id")).First(&patient).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	if err := hospital.DB.Delete(&patient).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete patient"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": true})
}
