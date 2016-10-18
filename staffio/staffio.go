package staffio

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"golang.org/x/oauth2"
)

type InfoToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresIn    int64     `json:"expires_in,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	Me           User      `json:"me,omitempty"`
}

// User is a retrieved and authenticated user.
type User struct {
	Uid            string `json:"uid"`                                // 登录名
	CommonName     string `json:"cn,omitempty"`                       // 全名
	GivenName      string `json:"gn" form:"gn" binding:"required"`    // 名
	Surname        string `json:"sn" form:"sn" binding:"required"`    // 姓
	Nickname       string `json:"nickname,omitempty" form:"nickname"` // 昵称
	Birthday       string `json:"birthday,omitempty" form:"birthday"`
	Gender         string `json:"gender,omitempty"`
	Mobile         string `json:"mobile,omitempty"`
	Email          string `json:"email,omitempty"`
	EmployeeNumber string `json:"eid,omitempty" form:"eid"`
	EmployeeType   string `json:"etype,omitempty" form:"etitle"`
	AvatarPath     string `json:"avatarPath,omitempty" form:"avatar"`
}

const (
	KeyState = "_state"
	KeyToken = "_tok"
)

var (
	conf           *oauth2.Config
	oAuth2Endpoint oauth2.Endpoint
	infoUrl        string
)

func init() {
	prefix := getEnv("STAFFIO_PREFIX", "https://staffio.work")
	oAuth2Endpoint = oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/%s", prefix, "authorize"),
		TokenURL: fmt.Sprintf("%s/%s", prefix, "token"),
	}
	infoUrl = fmt.Sprintf("%s/%s", prefix, "info/me")
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Setup oauth2 config
func Setup(redirectURL, clientID, clientSecret string, scopes []string) {
	conf = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     oAuth2Endpoint,
	}
}

func LoginHandler(ctx *gin.Context) {
	state := randToken()
	ctx.SetCookie(KeyState, state, 0, "/", "", false, true)
	location := GetLoginURL(state)
	ctx.Header("refresh", fmt.Sprintf("1; %s", location))
	ctx.Writer.Write([]byte("<html><title>Staffio</title> <body style='padding: 2em;'> <p>Waiting...</p> <a href='" + location + "'><button style='font-size: 14px;'> Login with Staffio! </button> </a> </body></html>"))
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Handle the exchange code to initiate a transport.
		retrievedState, err := ctx.Cookie(KeyState)
		if err != nil || retrievedState != ctx.Query("state") {
			log.Printf("state:\n%s\n%s", retrievedState, ctx.Query("state"))
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid state: %s", retrievedState))
			return
		}

		tok, err := conf.Exchange(oauth2.NoContext, ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}
		log.Printf("tok: %s", tok)

		client := conf.Client(oauth2.NoContext, tok)
		info, err := client.Get(infoUrl)
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}
		defer info.Body.Close()
		data, err := ioutil.ReadAll(info.Body)
		if err != nil {
			glog.Errorf("[Gin-OAuth] Could not read Body: %s", err)
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		log.Print(string(data))
		var token InfoToken
		err = json.Unmarshal(data, &token)
		if err != nil {
			glog.Errorf("[Gin-OAuth] Unmarshal userinfo failed: %s", err)
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		// save userinfo, which could be used in Handlers
		ctx.Set(KeyToken, token)
	}
}

func getEnv(key, dft string) string {
	v := os.Getenv(key)
	if v == "" {
		return dft
	}
	return v
}
