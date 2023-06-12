package doctorhandler

import (
	"fmt"
	"net/http"
	"HospitalFinpro/hospital"
	"github.com/gin-gonic/gin"
)

func SelectAll(c *gin.Context) {
	var doctors []hospital.Doctor
	hospital.DB.Find(&doctors)

	var doctorResponses []hospital.DoctorResponse
	for _, doctor := range doctors {
		doctorResponse := hospital.DoctorResponse{
			DoctorID:      doctor.DoctorID,
			DoctorName:    doctor.DoctorName,
			DoctorLicense: doctor.DoctorLicense,
		}
		doctorResponses = append(doctorResponses, doctorResponse)
	}

	c.JSON(http.StatusOK, gin.H{"data": doctorResponses})
}

func Create(c *gin.Context) {
	var doctorInput hospital.DoctorInput
	if err := c.ShouldBindJSON(&doctorInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	doctor := hospital.Doctor{
		DoctorName:    doctorInput.DoctorName,
		DoctorLicense: doctorInput.DoctorLicense,
	}

	if err := hospital.DB.Create(&doctor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create doctor"})
		return
	}

	doctorResponse := hospital.DoctorResponse{
		DoctorID:      doctor.DoctorID,
		DoctorName:    doctor.DoctorName,
		DoctorLicense: doctor.DoctorLicense,
	}

	c.JSON(http.StatusOK, gin.H{"data": doctorResponse})
}

func Read(c *gin.Context) {
	var doctor hospital.Doctor
	if err := hospital.DB.Where("doctor_id = ?", c.Param("id")).First(&doctor).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DATA TIDAK DITEMUKAN!"})
		return
	}

	doctorResponse := hospital.DoctorResponse{
		DoctorID:      doctor.DoctorID,
		DoctorName:    doctor.DoctorName,
		DoctorLicense: doctor.DoctorLicense,
	}

	c.JSON(http.StatusOK, gin.H{"data": doctorResponse})
}

func Update(c *gin.Context) {
	var doctor hospital.Doctor
	fmt.Println(c.Param("id"))
	if err := hospital.DB.Where("doctor_id = ?", c.Param("id")).First(&doctor).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DATA TIDAK DITEMUKAN!"})
		return
	}

	var doctorInput hospital.DoctorInput
	if err := c.ShouldBindJSON(&doctorInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	doctor.DoctorName = doctorInput.DoctorName
	doctor.DoctorLicense = doctorInput.DoctorLicense

	if err := hospital.DB.Save(&doctor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update doctor"})
		return
	}

	doctorResponse := hospital.DoctorResponse{
		DoctorID:      doctor.DoctorID,
		DoctorName:    doctor.DoctorName,
		DoctorLicense: doctor.DoctorLicense,
	}

	c.JSON(http.StatusOK, gin.H{"data": doctorResponse})
}

func Delete(c *gin.Context) {
	var doctor hospital.Doctor
	if err := hospital.DB.Where("doctor_id = ?", c.Param("id")).First(&doctor).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DATA TIDAK DITEMUKAN!"})
		return
	}

	if err := hospital.DB.Delete(&doctor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete doctor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": true})
}
