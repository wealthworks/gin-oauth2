package staffio

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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

func (tok *InfoToken) GetExpiry() time.Time {
	return time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
}

// for redux-auth
func (tok *InfoToken) GetAuthedUrl(authUrl string) string {
	var buf bytes.Buffer
	buf.WriteString(authUrl)
	v := url.Values{
		"access_token": {tok.AccessToken},
		"client_id":    {conf.ClientID},
		"uid":          {tok.Me.Uid},
		"expiry":       {fmt.Sprintf("%d", tok.GetExpiry().Unix())},
	}

	buf.WriteByte('?')
	buf.WriteString(v.Encode())
	return buf.String()
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
	Provider       string `json:"provider"`
}

type infoError struct {
	Code    string `json:"error"`
	Message string `json:"error_description,omitempty"`
}

func (e *infoError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
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
	location := GetAuthCodeURL(state)
	ctx.Header("refresh", fmt.Sprintf("1; %s", location))
	ctx.Writer.Write([]byte("<html><title>Staffio</title> <body style='padding: 2em;'> <p>Waiting...</p> <a href='" + location + "'><button style='font-size: 14px;'> Login with Staffio! </button> </a> </body></html>"))
}

func TokenHandler(ctx *gin.Context) {
	state := randToken()
	ctx.SetCookie(KeyState, state, 0, "/", "", false, true)
	location := GetAuthTokenURL(state)
	ctx.Header("refresh", fmt.Sprintf("1; %s", location))
	ctx.Writer.Write([]byte("<html><title>Staffio</title> <body style='padding: 2em;'> <p>Waiting...</p> <a href='" + location + "'><button style='font-size: 14px;'> Login with Staffio! </button> </a> </body></html>"))
}

func GetAuthCodeURL(state string) string {
	return conf.AuthCodeURL(state)
}

func GetAuthTokenURL(state string) string {
	var buf bytes.Buffer
	buf.WriteString(conf.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"token"},
		"client_id":     {conf.ClientID},
		"redirect_uri":  {conf.RedirectURL},
		"scope":         {strings.Join(conf.Scopes, " ")},
		"state":         {state},
	}

	buf.WriteByte('?')
	buf.WriteString(v.Encode())
	return buf.String()
}

// auth callback with authCode
func AuthCodeCallback() gin.HandlerFunc {
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
		// log.Printf("tok: %s", tok)

		token, err := requestInfoToken(tok)
		if err != nil {
			log.Printf("requestInfoToken err %s", err)
			ctx.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		// save userinfo, which could be used in Handlers
		ctx.Set(KeyToken, token)
	}
}

func AuthToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tok, err := extractToken(ctx.Request)
		if err != nil {
			log.Printf("extractToken err", err)
			ctx.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		if !tok.Valid() {
			log.Printf("Invalid Token - nil or expired")
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("invalid token: %q", tok.AccessToken))
			return
		}

		token, err := requestInfoToken(tok)
		if err != nil {
			log.Printf("requestInfoToken err %s", err)
			ctx.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		// save userinfo, which could be used in Handlers
		ctx.Set(KeyToken, token)
	}
}

func requestInfoToken(tok *oauth2.Token) (*InfoToken, error) {
	client := conf.Client(oauth2.NoContext, tok)
	info, err := client.Get(infoUrl)
	if err != nil {
		return nil, err
	}
	defer info.Body.Close()
	data, err := ioutil.ReadAll(info.Body)
	if err != nil {
		log.Printf("read err %s", err)
		return nil, err
	}
	log.Print(string(data))

	infoErr := &infoError{}
	if e := json.Unmarshal(data, infoErr); e != nil {
		return nil, e
	}

	if infoErr.Code != "" {
		return nil, infoErr
	}

	var token = &InfoToken{}
	err = json.Unmarshal(data, token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func extractToken(r *http.Request) (*oauth2.Token, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, errors.New("No authorization header")
	}

	th := strings.Split(hdr, " ")
	if len(th) != 2 {
		return nil, errors.New("Incomplete authorization header")
	}

	return &oauth2.Token{AccessToken: th[1], TokenType: th[0]}, nil
}

func getEnv(key, dft string) string {
	v := os.Getenv(key)
	if v == "" {
		return dft
	}
	return v
}
