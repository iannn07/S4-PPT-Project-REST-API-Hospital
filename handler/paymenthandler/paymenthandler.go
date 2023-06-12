package paymenthandler

import (
	"net/http"
	"HospitalFinpro/hospital"
	"github.com/gin-gonic/gin"
)

func SelectAll(c *gin.Context) {
	var payments []hospital.Payment
	hospital.DB.Find(&payments)

	var paymentResponses []hospital.PaymentResponse
	for _, payment := range payments {
		paymentResponse := hospital.PaymentResponse{
			PayID:     payment.PayID,
			PatientID: payment.PatientID,
			PayTotal:  payment.PayTotal,
		}
		paymentResponses = append(paymentResponses, paymentResponse)
	}

	c.JSON(http.StatusOK, gin.H{"data": paymentResponses})
}

func Create(c *gin.Context) {
	var paymentInput hospital.PaymentInput
	if err := c.ShouldBindJSON(&paymentInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	payment := hospital.Payment{
		PatientID: paymentInput.PatientID,
		PayTotal:  paymentInput.PayTotal,
	}
	if err := hospital.DB.Create(&payment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create payment"})
		return
	}

	paymentResponse := hospital.PaymentResponse{
		PayID:     payment.PayID,
		PatientID: payment.PatientID,
		PayTotal:  payment.PayTotal,
	}

	c.JSON(http.StatusOK, gin.H{"data": paymentResponse})
}

func Read(c *gin.Context) {
	var payment hospital.Payment
	if err := hospital.DB.Where("pay_id = ?", c.Param("id")).First(&payment).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	paymentResponse := hospital.PaymentResponse{
		PayID:     payment.PayID,
		PatientID: payment.PatientID,
		PayTotal:  payment.PayTotal,
	}

	c.JSON(http.StatusOK, gin.H{"data": paymentResponse})
}

func Update(c *gin.Context) {
	var payment hospital.Payment
	if err := hospital.DB.Where("pay_id = ?", c.Param("id")).First(&payment).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	var paymentInput hospital.PaymentInput
	if err := c.ShouldBindJSON(&paymentInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	payment.PatientID = paymentInput.PatientID
	payment.PayTotal = paymentInput.PayTotal

	if err := hospital.DB.Save(&payment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update payment"})
		return
	}

	paymentResponse := hospital.PaymentResponse{
		PayID:     payment.PayID,
		PatientID: payment.PatientID,
		PayTotal:  payment.PayTotal,
	}

	c.JSON(http.StatusOK, gin.H{"data": paymentResponse})
}

func Delete(c *gin.Context) {
	var payment hospital.Payment
	if err := hospital.DB.Where("pay_id = ?", c.Param("id")).First(&payment).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	if err := hospital.DB.Delete(&payment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete payment"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": true})
}
