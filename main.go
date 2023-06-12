package main

import (
	"HospitalFinpro/handler/diagnosehandler"
	"HospitalFinpro/handler/doctorhandler"
	"HospitalFinpro/handler/patienthandler"
	"HospitalFinpro/handler/paymenthandler"
	"HospitalFinpro/handler/roomhandler"
	"HospitalFinpro/hospital"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	hospital.ConnectDB()

	/* [#] list Order Route :
	 *     1. Add Doctor
	 *     2. Add Patient and DoctorID (foreign key)
	 *     3. Add Room and PatientID (foreign key)
	 *     4. Add Diagnose, PatientID (foreign key), and DoctorID (foreign key)
	 *     5. Add Paymenta and PatientID (foreign key)
	 */

	// Doctor routes
	router.GET("api/hospital/doctors", doctorhandler.SelectAll)
	router.POST("api/hospital/doctors", doctorhandler.Create)
	router.GET("api/hospital/doctors/:id", doctorhandler.Read)
	router.PUT("api/hospital/doctors/:id", doctorhandler.Update)
	router.DELETE("api/hospital/doctors/:id", doctorhandler.Delete)

	// Patient routes
	router.GET("api/hospital/patients", patienthandler.SelectAll)
	router.POST("api/hospital/patients", patienthandler.Create)
	router.GET("api/hospital/patients/:id", patienthandler.Read)
	router.PUT("api/hospital/patients/:id", patienthandler.Update)
	router.DELETE("api/hospital/patients/:id", patienthandler.Delete)

	// Room routes
	router.GET("api/hospital/rooms", roomhandler.SelectAll)
	router.POST("api/hospital/rooms", roomhandler.Create)
	router.GET("api/hospital/rooms/:id", roomhandler.Read)
	router.PUT("api/hospital/rooms/:id", roomhandler.Update)
	router.DELETE("api/hospital/rooms/:id", roomhandler.Delete)

	// Diagnose routes
	router.GET("api/hospital/diagnoses", diagnosehandler.SelectAll)
	router.POST("api/hospital/diagnoses", diagnosehandler.Create)
	router.GET("api/hospital/diagnoses/:id", diagnosehandler.Read)
	router.PUT("api/hospital/diagnoses/:id", diagnosehandler.Update)
	router.DELETE("api/hospital/diagnoses/:id", diagnosehandler.Delete)

	// Payment routes
	router.GET("api/hospital/payments", paymenthandler.SelectAll)
	router.POST("api/hospital/payments", paymenthandler.Create)
	router.GET("api/hospital/payments/:id", paymenthandler.Read)
	router.PUT("api/hospital/payments/:id", paymenthandler.Update)
	router.DELETE("api/hospital/payments/:id", paymenthandler.Delete)

	// Route Prefix Address
	router.Run("localhost:8080")
}
