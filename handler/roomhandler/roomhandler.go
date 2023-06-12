package roomhandler

import (
	"net/http"
	"HospitalFinpro/hospital"
	"github.com/gin-gonic/gin"
)

func SelectAll(c *gin.Context) {
	var rooms []hospital.Room
	hospital.DB.Find(&rooms)

	var roomResponses []hospital.RoomResponse
	for _, room := range rooms {
		roomResponse := hospital.RoomResponse{
			RoomID:    room.RoomID,
			PatientID: room.PatientID,
			RoomType:  room.RoomType,
		}
		roomResponses = append(roomResponses, roomResponse)
	}

	c.JSON(http.StatusOK, gin.H{"data": roomResponses})
}

func Create(c *gin.Context) {
	var roomInput hospital.RoomInput
	if err := c.ShouldBindJSON(&roomInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	room := hospital.Room{
		PatientID: roomInput.PatientID,
		RoomType:  roomInput.RoomType,
	}
	hospital.DB.Create(&room)

	roomResponse := hospital.RoomResponse{
		RoomID:    room.RoomID,
		PatientID: room.PatientID,
		RoomType:  room.RoomType,
	}

	c.JSON(http.StatusOK, gin.H{"data": roomResponse})
}

func Read(c *gin.Context) {
	var room hospital.Room
	if err := hospital.DB.Where("room_id = ?", c.Param("id")).First(&room).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	roomResponse := hospital.RoomResponse{
		RoomID:    room.RoomID,
		PatientID: room.PatientID,
		RoomType:  room.RoomType,
	}

	c.JSON(http.StatusOK, gin.H{"data": roomResponse})
}

func Update(c *gin.Context) {
	var room hospital.Room
	if err := hospital.DB.Where("room_id = ?", c.Param("id")).First(&room).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	var roomInput hospital.RoomInput
	if err := c.ShouldBindJSON(&roomInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	room.PatientID = roomInput.PatientID
	room.RoomType = roomInput.RoomType
	hospital.DB.Save(&room)

	roomResponse := hospital.RoomResponse{
		RoomID:    room.RoomID,
		PatientID: room.PatientID,
		RoomType:  room.RoomType,
	}

	c.JSON(http.StatusOK, gin.H{"data": roomResponse})
}

func Delete(c *gin.Context) {
	var room hospital.Room
	if err := hospital.DB.Where("room_id = ?", c.Param("id")).First(&room).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "NO DATA!"})
		return
	}

	hospital.DB.Delete(&room)

	c.JSON(http.StatusOK, gin.H{"data": true})
}
