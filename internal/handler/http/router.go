package http

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"

	"github.com/qinzj/ums-ldap/internal/config"
	"github.com/qinzj/ums-ldap/internal/middleware"
	"github.com/qinzj/ums-ldap/internal/service"
)

// SetupRouter creates and configures the Gin router with all routes.
func SetupRouter(
	userSvc *service.UserService,
	groupSvc *service.GroupService,
	authSvc *service.AuthService,
	ldapCfg *config.LDAPConfig,
	logger *zap.Logger,
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.Logger(logger))

	authHandler := NewAuthHandler(authSvc)
	userHandler := NewUserHandler(userSvc, groupSvc)
	groupHandler := NewGroupHandler(groupSvc)
	ldapHandler := NewLDAPConfigHandler(ldapCfg)

	// Swagger UI: GET /swagger/index.html
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api := r.Group("/api/v1")
	{
		api.POST("/auth/login", authHandler.Login)
		api.POST("/auth/logout", authHandler.Logout)
		api.POST("/users", userHandler.Create)

		protected := api.Group("")
		protected.Use(middleware.JWTAuth(authSvc))
		{
			protected.GET("/users", userHandler.List)
			protected.GET("/users/:id", userHandler.Get)
			protected.PUT("/users/:id", userHandler.Update)
			protected.DELETE("/users/:id", userHandler.Delete)
			protected.PUT("/users/:id/password", userHandler.ChangePassword)
			protected.PUT("/users/:id/status", userHandler.SetStatus)
			protected.GET("/users/:id/groups", userHandler.GetGroups)

			protected.POST("/groups", groupHandler.Create)
			protected.GET("/groups", groupHandler.List)
			protected.GET("/groups/:id", groupHandler.Get)
			protected.PUT("/groups/:id", groupHandler.Update)
			protected.DELETE("/groups/:id", groupHandler.Delete)
			protected.POST("/groups/:id/members", groupHandler.AddMembers)
			protected.DELETE("/groups/:id/members/:uid", groupHandler.RemoveMember)
			protected.GET("/groups/:id/members", groupHandler.GetMembers)

			protected.GET("/ldap/config", ldapHandler.GetConfig)
			protected.PUT("/ldap/config", ldapHandler.UpdateConfig)
			protected.GET("/ldap/status", ldapHandler.GetStatus)
		}
	}

	return r
}
