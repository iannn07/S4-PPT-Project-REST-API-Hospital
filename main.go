package main

import (
	"HospitalFinpro/handler/diagnosehandler"
	"HospitalFinpro/handler/doctorhandler"
	"HospitalFinpro/handler/patienthandler"
	"HospitalFinpro/handler/paymenthandler"
	"HospitalFinpro/handler/roomhandler"
	"HospitalFinpro/hospital"
	"errors"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var (
	secretKey      = "pass123"
	invalidatedMap = make(map[string]bool)
)

// GenerateJWT generates a new JWT token using the provided secret key
func GenerateJWT(userID string, secretKey string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour) // Token valid for 1 hours

	// Create the claims
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Subject:   userID,
	}

	// Generate the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// VerifyJWT verifies the JWT token and returns the user ID
func VerifyJWT(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token")
	}

	return claims.Subject, nil
}

// LoginHandler handles
func LoginHandler(c *gin.Context) {
	// Get the secret key from the Authorization header
	secretKey := c.GetHeader("Authorization")

	if secretKey != "pass123" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userID := "user123"

	token, err := GenerateJWT(userID, secretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// LogoutHandler handles the logout request and invalidates the JWT token
func LogoutHandler(c *gin.Context) {
	// Get the JWT token from the Authorization header
	tokenString := c.Request.Header.Get("Authorization")

	invalidatedMap[tokenString] = true

	// Clear the user's session
	c.Set("userID", "")

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the JWT token from the Authorization header
		tokenString := c.Request.Header.Get("Authorization")

		// Check if the token is in the invalidatedMap
		if invalidatedMap[tokenString] {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Verify the JWT token and extract the user ID
		userID, err := VerifyJWT(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Set the user ID on the context
		c.Set("userID", userID)
	}
}

func main() {
	router := gin.Default()
	hospital.ConnectDB()

	/* [#] list Order Route :
	 *     1. Add Doctor
	 *     2. Add Patient and DoctorID (foreign key)
	 *     3. Add Room and PatientID (foreign key)
	 *     4. Add Diagnose, PatientID (foreign key), and DoctorID (foreign key)
	 *     5. Add Payments and PatientID (foreign key)
	 */

	// authMiddleware := func(c *gin.Context) {
	// 	// Get the JWT token from the Authorization header
	// 	tokenString := c.Request.Header.Get("Authorization")

	// 	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
	// 		// The secret key is used to verify the JWT token
	// 		return []byte(secretKey), nil
	// 	})

	// 	if err != nil || !token.Valid {
	// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
	// 		c.Abort()
	// 		return
	// 	}

	// 	claims, ok := token.Claims.(*jwt.StandardClaims)
	// 	if !ok {
	// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
	// 		c.Abort()
	// 		return
	// 	}

	// 	// Set the user ID on the context
	// 	c.Set("userID", claims.Subject)
	// }

	router.POST("api/login", LoginHandler)
	router.POST("api/logout", LogoutHandler)

	// Protected routes
	protected := router.Group("/api")
	protected.Use(AuthMiddleware())
	{
		// Doctor routes
		protected.GET("/hospital/doctors", doctorhandler.SelectAll)
		protected.POST("/hospital/doctors", doctorhandler.Create)
		protected.GET("/hospital/doctors/:id", doctorhandler.Read)
		protected.PUT("/hospital/doctors/:id", doctorhandler.Update)
		protected.DELETE("/hospital/doctors/:id", doctorhandler.Delete)
	}
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
