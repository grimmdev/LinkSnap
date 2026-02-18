package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const DBName = "data/linksnap.db"

//go:embed public
var embedDir embed.FS

type User struct {
	gorm.Model
	Email        string `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string `json:"-"`
	Name         string `json:"name"`
	AvatarURL    string `json:"avatar_url"`
	Role         string `json:"role" gorm:"default:'user'"`
	IsOnboarded  bool   `json:"is_onboarded" gorm:"default:false"`
}

type Link struct {
	gorm.Model
	URL            string `json:"url" gorm:"not null"`
	Title          string `json:"title"`
	ScreenshotPath string `json:"screenshot_path"`
	UserID         uint   `json:"user_id"`
	FolderID       *uint  `json:"folder_id"`
	IsFavorite     bool   `json:"is_favorite" gorm:"default:false"`
	IsArchived     bool   `json:"is_archived" gorm:"default:false"`
	Tags           []Tag  `json:"tags" gorm:"many2many:link_tags;"`
}

type Folder struct {
	gorm.Model
	Name   string `json:"name" gorm:"not null"`
	UserID uint   `json:"user_id"`
}

type Tag struct {
	gorm.Model
	Name   string `json:"name"`
	Color  string `json:"color"`
	UserID uint   `json:"user_id"`
}

type RegisterInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateUserInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type OnboardInput struct {
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type LinkInput struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	FolderID   *uint  `json:"folder_id"`
	TagIDs     []uint `json:"tag_ids"`
	IsFavorite *bool  `json:"is_favorite"`
	IsArchived *bool  `json:"is_archived"`
}

type FolderInput struct {
	Name string `json:"name"`
}

type TagInput struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

var DB *gorm.DB
var StartTime time.Time
var SecretKey string
var SnapshotFormat string
var publicFS fs.FS

func ConnectDB() {
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		os.Mkdir("data", 0755)
	}

	var err error
	DB, err = gorm.Open(sqlite.Open(DBName), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	log.Println("Database connected successfully")
	DB.AutoMigrate(&User{}, &Link{}, &Folder{}, &Tag{})
}

func getScreenshotURL(targetURL string) string {
	encoded := url.QueryEscape(targetURL)
	return strings.ReplaceAll(SnapshotFormat, "{url}", encoded)
}

func getUserIDFromToken(c *fiber.Ctx) uint {
	return c.Locals("user_id").(uint)
}

func serveEmbed(fileName string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		content, err := fs.ReadFile(publicFS, fileName)
		if err != nil {
			log.Printf("EMBED ERROR: Could not find file '%s' in binary. Current FS root: .", fileName)
			return c.Status(404).SendString(fmt.Sprintf("File not found in bundle: %s", fileName))
		}
		c.Set("Content-Type", "text/html")
		return c.Send(content)
	}
}

func RegisterFirstUser(c *fiber.Ctx) error {
	var input RegisterInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	var count int64
	DB.Model(&User{}).Count(&count)
	if count > 0 {
		return c.Status(403).JSON(fiber.Map{"error": "Registration is closed."})
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(input.Password), 14)
	user := User{Email: input.Email, PasswordHash: string(hashedPassword), Role: "admin", Name: "Admin", IsOnboarded: true}
	DB.Create(&user)
	return c.JSON(user)
}

func Login(c *fiber.Ctx) error {
	var input LoginInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	var user User
	if err := DB.Where("email = ?", input.Email).First(&user).Error; err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.ID
	claims["role"] = user.Role
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	t, _ := token.SignedString([]byte(SecretKey))
	return c.JSON(fiber.Map{"token": t, "user": user})
}

func GetMe(c *fiber.Ctx) error {
	userID := getUserIDFromToken(c)
	var user User
	if err := DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}
	return c.JSON(user)
}

func OnboardUser(c *fiber.Ctx) error {
	userID := getUserIDFromToken(c)
	var input OnboardInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	var user User
	DB.First(&user, userID)
	user.Name = input.Name
	user.AvatarURL = input.AvatarURL
	user.IsOnboarded = true
	DB.Save(&user)
	return c.JSON(user)
}

func CreateLink(c *fiber.Ctx) error {
	userID := getUserIDFromToken(c)
	var input LinkInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	screenshotURL := getScreenshotURL(input.URL)

	link := Link{
		URL:            input.URL,
		Title:          input.Title,
		ScreenshotPath: screenshotURL,
		UserID:         userID,
		FolderID:       input.FolderID,
	}

	if len(input.TagIDs) > 0 {
		var tags []Tag
		DB.Where("id IN ? AND user_id = ?", input.TagIDs, userID).Find(&tags)
		link.Tags = tags
	}

	DB.Create(&link)
	return c.JSON(link)
}

func GetLinks(c *fiber.Ctx) error {
	userID := getUserIDFromToken(c)
	var links []Link
	DB.Preload("Tags").Where("user_id = ?", userID).Order("created_at desc").Find(&links)
	return c.JSON(links)
}

func UpdateLink(c *fiber.Ctx) error {
	id := c.Params("id")
	userID := getUserIDFromToken(c)
	var link Link
	if err := DB.Where("id = ? AND user_id = ?", id, userID).First(&link).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Link not found"})
	}

	var input LinkInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	if input.URL != "" {
		link.URL = input.URL
		link.ScreenshotPath = getScreenshotURL(input.URL)
	}
	if input.Title != "" {
		link.Title = input.Title
	}
	link.FolderID = input.FolderID
	if input.IsFavorite != nil {
		link.IsFavorite = *input.IsFavorite
	}
	if input.IsArchived != nil {
		link.IsArchived = *input.IsArchived
	}

	if input.TagIDs != nil {
		var tags []Tag
		DB.Where("id IN ? AND user_id = ?", input.TagIDs, userID).Find(&tags)
		DB.Model(&link).Association("Tags").Replace(tags)
	}

	DB.Save(&link)
	return c.JSON(link)
}

func DeleteLink(c *fiber.Ctx) error {
	id := c.Params("id")
	userID := getUserIDFromToken(c)
	DB.Where("id = ? AND user_id = ?", id, userID).Delete(&Link{})
	return c.SendStatus(200)
}

func GetFolders(c *fiber.Ctx) error {
	userID := getUserIDFromToken(c)
	var folders []Folder
	DB.Where("user_id = ?", userID).Find(&folders)
	return c.JSON(folders)
}
func CreateFolder(c *fiber.Ctx) error {
	userID := getUserIDFromToken(c)
	var input FolderInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	folder := Folder{Name: input.Name, UserID: userID}
	DB.Create(&folder)
	return c.JSON(folder)
}
func UpdateFolder(c *fiber.Ctx) error {
	id := c.Params("id")
	userID := getUserIDFromToken(c)
	var folder Folder
	if err := DB.Where("id = ? AND user_id = ?", id, userID).First(&folder).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Folder not found"})
	}
	var input FolderInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	folder.Name = input.Name
	DB.Save(&folder)
	return c.JSON(folder)
}
func DeleteFolder(c *fiber.Ctx) error {
	id := c.Params("id")
	userID := getUserIDFromToken(c)
	DB.Model(&Link{}).Where("folder_id = ? AND user_id = ?", id, userID).Update("folder_id", nil)
	DB.Where("id = ? AND user_id = ?", id, userID).Delete(&Folder{})
	return c.SendStatus(200)
}

func GetTags(c *fiber.Ctx) error {
	userID := getUserIDFromToken(c)
	var tags []Tag
	DB.Where("user_id = ?", userID).Find(&tags)
	return c.JSON(tags)
}
func CreateTag(c *fiber.Ctx) error {
	userID := getUserIDFromToken(c)
	var input TagInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	tag := Tag{Name: input.Name, Color: input.Color, UserID: userID}
	DB.Create(&tag)
	return c.JSON(tag)
}
func UpdateTag(c *fiber.Ctx) error {
	id := c.Params("id")
	userID := getUserIDFromToken(c)
	var tag Tag
	if err := DB.Where("id = ? AND user_id = ?", id, userID).First(&tag).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Tag not found"})
	}
	var input TagInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	tag.Name = input.Name
	tag.Color = input.Color
	DB.Save(&tag)
	return c.JSON(tag)
}
func DeleteTag(c *fiber.Ctx) error {
	id := c.Params("id")
	userID := getUserIDFromToken(c)
	var tag Tag
	if err := DB.Where("id = ? AND user_id = ?", id, userID).First(&tag).Error; err == nil {
		DB.Model(&tag).Association("Links").Clear()
	}
	DB.Where("id = ? AND user_id = ?", id, userID).Delete(&Tag{})
	return c.SendStatus(200)
}

func AdminCreateUser(c *fiber.Ctx) error {
	var input CreateUserInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(input.Password), 14)
	user := User{Email: input.Email, PasswordHash: string(hashedPassword), Name: input.Name, Role: "user"}
	if result := DB.Create(&user); result.Error != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Could not create user."})
	}
	return c.JSON(user)
}
func GetSystemStatus(c *fiber.Ctx) error {
	var userCount, linkCount int64
	DB.Model(&User{}).Count(&userCount)
	DB.Model(&Link{}).Count(&linkCount)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return c.JSON(fiber.Map{
		"uptime":       time.Since(StartTime).Round(time.Second).String(),
		"users_count":  userCount,
		"links_count":  linkCount,
		"memory_usage": fmt.Sprintf("%v MiB", m.Sys/1024/1024),
	})
}

func Protected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := c.Get("Authorization")
		if len(tokenString) < 7 || tokenString[:7] != "Bearer " {
			return c.Status(401).JSON(fiber.Map{"error": "Missing JWT"})
		}
		token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) { return []byte(SecretKey), nil })
		if err != nil || !token.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid token"})
		}
		claims := token.Claims.(jwt.MapClaims)
		c.Locals("user_id", uint(claims["user_id"].(float64)))
		c.Locals("role", claims["role"].(string))
		return c.Next()
	}
}
func AdminOnly(c *fiber.Ctx) error {
	if c.Locals("role").(string) != "admin" {
		return c.Status(403).JSON(fiber.Map{"error": "Admin only"})
	}
	return c.Next()
}

func main() {
	var err error
	publicFS, err = fs.Sub(embedDir, "public")
	if err != nil {
		log.Fatal("Failed to create sub-filesystem for public folder:", err)
	}

	SecretKey = os.Getenv("SECRET_KEY")
	if SecretKey == "" {
		SecretKey = "secret"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	SnapshotFormat = os.Getenv("SNAPSHOT_API_FORMAT")
	if SnapshotFormat == "" {
		SnapshotFormat = "https://s0.wp.com/mshots/v1/{url}?w=1280&h=720"
	}

	StartTime = time.Now()
	ConnectDB()

	app := fiber.New()
	app.Use(logger.New())
	app.Use(cors.New())

	app.Get("/", serveEmbed("index.html"))
	app.Get("/dashboard", serveEmbed("dashboard.html"))

	api := app.Group("/api")
	api.Post("/register", RegisterFirstUser)
	api.Post("/login", Login)

	userRoutes := api.Group("/users", Protected())
	userRoutes.Get("/me", GetMe)
	userRoutes.Put("/me", OnboardUser)

	featRoutes := api.Group("/", Protected())
	featRoutes.Post("/links", CreateLink)
	featRoutes.Get("/links", GetLinks)
	featRoutes.Put("/links/:id", UpdateLink)
	featRoutes.Delete("/links/:id", DeleteLink)
	featRoutes.Post("/folders", CreateFolder)
	featRoutes.Get("/folders", GetFolders)
	featRoutes.Put("/folders/:id", UpdateFolder)
	featRoutes.Delete("/folders/:id", DeleteFolder)
	featRoutes.Post("/tags", CreateTag)
	featRoutes.Get("/tags", GetTags)
	featRoutes.Put("/tags/:id", UpdateTag)
	featRoutes.Delete("/tags/:id", DeleteTag)

	adminRoutes := api.Group("/admin", Protected(), AdminOnly)
	adminRoutes.Post("/users", AdminCreateUser)
	adminRoutes.Get("/status", GetSystemStatus)

	log.Println("Server on :" + port)
	app.Listen(":" + port)
}
