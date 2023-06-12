package diagnosehandler

import (
	"net/http"
	"HospitalFinpro/hospital"
	"github.com/gin-gonic/gin"
)

func SelectAll(c *gin.Context) {
	var diagnoses []hospital.Diagnose
	hospital.DB.Find(&diagnoses)

	var diagnoseResponses []hospital.DiagnoseResponse
	for _, diagnose := range diagnoses {
		diagnoseResponse := hospital.DiagnoseResponse{
			DiagnosisID:          diagnose.DiagnoseID,
			DiagnosisDate:		  diagnose.DiagnosisDate,
			DiagnosisDescription: diagnose.DiagnosisDescription,
			PatientID:            diagnose.PatientID,
			DoctorID:             diagnose.DoctorID,
		}
		diagnoseResponses = append(diagnoseResponses, diagnoseResponse)
	}

	c.JSON(http.StatusOK, gin.H{"data": diagnoseResponses})
}

func Create(c *gin.Context) {
	var diagnoseInput hospital.DiagnoseInput
	if err := c.ShouldBindJSON(&diagnoseInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	diagnose := hospital.Diagnose{
		DiagnosisDate:		  diagnoseInput.DiagnosisDate,
		DiagnosisDescription: diagnoseInput.DiagnosisDescription,
		PatientID:            diagnoseInput.PatientID,
		DoctorID:             diagnoseInput.DoctorID,
	}

	if err := hospital.DB.Create(&diagnose).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create diagnose"})
		return
	}

	diagnoseResponse := hospital.DiagnoseResponse{
		DiagnosisID:          diagnose.DiagnoseID,
		DiagnosisDate:		  diagnoseInput.DiagnosisDate,
		DiagnosisDescription: diagnose.DiagnosisDescription,
		PatientID:            diagnose.PatientID,
		DoctorID:             diagnose.DoctorID,
	}

	c.JSON(http.StatusOK, gin.H{"data": diagnoseResponse})
}

func Read(c *gin.Context) {
	var diagnose hospital.Diagnose
	if err := hospital.DB.Where("diagnosis_id = ?", c.Param("id")).Preload("Patient").Preload("Doctor").First(&diagnose).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	diagnoseResponse := hospital.DiagnoseResponse{
		DiagnosisID:          diagnose.DiagnoseID,
		DiagnosisDate:		  diagnose.DiagnosisDate,
		DiagnosisDescription: diagnose.DiagnosisDescription,
		PatientID:            diagnose.PatientID,
		DoctorID:             diagnose.DoctorID,
	}

	c.JSON(http.StatusOK, gin.H{"data": diagnoseResponse})
}

func Update(c *gin.Context) {
	var diagnose hospital.Diagnose
	if err := hospital.DB.Where("diagnosis_id = ?", c.Param("id")).First(&diagnose).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	var diagnoseInput hospital.DiagnoseInput
	if err := c.ShouldBindJSON(&diagnoseInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	diagnose.DiagnosisDate =	  diagnoseInput.DiagnosisDate
	diagnose.DiagnosisDescription = diagnoseInput.DiagnosisDescription
	diagnose.PatientID = diagnoseInput.PatientID
	diagnose.DoctorID = diagnoseInput.DoctorID

	if err := hospital.DB.Save(&diagnose).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update diagnose"})
		return
	}

	diagnoseResponse := hospital.DiagnoseResponse{
		DiagnosisID:          diagnose.DiagnoseID,
		DiagnosisDate:		  diagnose.DiagnosisDate,
		DiagnosisDescription: diagnose.DiagnosisDescription,
		PatientID:            diagnose.PatientID,
		DoctorID:             diagnose.DoctorID,
	}

	c.JSON(http.StatusOK, gin.H{"data": diagnoseResponse})
}

func Delete(c *gin.Context) {
	var diagnose hospital.Diagnose
	if err := hospital.DB.Where("diagnosis_id = ?", c.Param("id")).First(&diagnose).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	if err := hospital.DB.Delete(&diagnose).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete diagnose"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": true})
}
