package service

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type CallBackConfig struct {
	ServiceName               string `json:"service_name"`
	Endpoint                  string `json:"endpoint"`
	TokenExpireMinutes        uint64 `json:"token_expire_minutes"`
	CallBackPubKeyPath        string `json:"callback_pub_key_path"`         // TSS Node的相应公钥
	CallBackHandlerPriKeyPath string `json:"callback_handler_pri_key_path"` // 本callback服务的私钥
	EnableDebug               bool   `json:"enable_debug"`
}

type CallBackService struct {
	CallBackPublicKey         *rsa.PublicKey
	CallBackHandlerPrivateKey *rsa.PrivateKey
	tokenExpireTime           time.Duration

	RcvWhiteListLock sync.Mutex
	RcvWhiteList     map[string]bool

	config *CallBackConfig
}

func NewCallBackService(config *CallBackConfig) *CallBackService {
	if config.Endpoint == "" || config.TokenExpireMinutes == 0 {
		return nil
	}

	csPubKey, cbPriKey, err := parserKey(config)
	if err != nil {
		panic(fmt.Sprintf("fail to parse public/private key: %v", err))
	}

	return &CallBackService{
		CallBackPublicKey:         csPubKey,
		CallBackHandlerPrivateKey: cbPriKey,
		tokenExpireTime:           time.Duration(config.TokenExpireMinutes) * time.Minute,
		config:                    config,
		RcvWhiteList:              make(map[string]bool),
	}
}

func parserKey(config *CallBackConfig) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	csPublicKeyByte, err := ioutil.ReadFile(config.CallBackPubKeyPath)
	if err != nil {
		return nil, nil, err
	}
	csPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(csPublicKeyByte)
	if err != nil {
		return nil, nil, err
	}

	cbPrivateKeyByte, err := ioutil.ReadFile(config.CallBackHandlerPriKeyPath)
	if err != nil {
		return nil, nil, err
	}
	cbPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(cbPrivateKeyByte)
	if err != nil {
		return nil, nil, err
	}

	return csPublicKey, cbPrivateKey, nil
}

func (rcs *CallBackService) Start() {
	r := gin.Default()
	if !rcs.config.EnableDebug {
		gin.SetMode(gin.ReleaseMode)
	}

	r.POST("/add_rcv_address", rcs.AddReceiverAddress)
	r.POST("/rm_rcv_address", rcs.RemoveReceiverAddress)
	r.GET("/list_rcv_address", rcs.ListReceiverAddress)

	api := r.Group("/v1")
	api.Use(rcs.jwtAuthMiddleware())
	api.POST("/check", rcs.RiskControl)

	log.Fatal(r.Run(rcs.config.Endpoint))
}

func (rcs *CallBackService) RiskControl(c *gin.Context) {
	req, err := rcs.GetRawRequest(c)
	if err != nil {
		rsp := CallBackResponse{
			Status:    StatusInvalidRequest,
			ErrStr:    err.Error(),
			RequestID: req.RequestID,
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}

	switch req.RequestType {
	case TypePing:
		rcs.processPingRequest(c, req.RequestID)
	case TypeKeyGen:
		rcs.processKeyGenRequest(c, req.RequestDetail, req.ExtraInfo, req.RequestID)
	case TypeKeySign:
		rcs.processKeySignRequest(c, req.RequestDetail, req.ExtraInfo, req.RequestID)
	case TypeKeyReshare:
		rcs.processKeyReShareRequest(c, req.RequestDetail, req.ExtraInfo, req.RequestID)
	}
}

func (rcs *CallBackService) processPingRequest(c *gin.Context, requestID string) {
	rsp := CallBackResponse{
		Status:    StatusOK,
		RequestID: requestID,
	}
	rcs.SendResponse(c, rsp)
}

func (rcs *CallBackService) processKeyGenRequest(c *gin.Context, rawRequest, extraInfo, requestID string) {
	kgDetail := KeyGenDetail{}
	if err := json.Unmarshal([]byte(rawRequest), &kgDetail); err != nil {
		rsp := CallBackResponse{
			Status:    StatusInternalError,
			ErrStr:    "fail to converse []byte to KeyGenDetail",
			RequestID: requestID,
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}

	rawExtraInfo := KeyGenExtraInfo{}
	if err := json.Unmarshal([]byte(extraInfo), &rawExtraInfo); err != nil {
		rsp := CallBackResponse{
			Status:    StatusInternalError,
			ErrStr:    "fail to converse []byte to KeyGenMeta",
			RequestID: requestID,
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}

	// risk control logical

	rsp := CallBackResponse{
		Action:    "APPROVE",
		RequestID: requestID,
		Status:    StatusOK,
	}

	rcs.SendResponse(c, rsp)
}

func (rcs *CallBackService) processKeySignRequest(c *gin.Context, rawRequest, extraInfo, requestID string) {
	ksDetail := KeySignDetail{}
	if err := json.Unmarshal([]byte(rawRequest), &ksDetail); err != nil {
		rsp := CallBackResponse{
			Status:    StatusInternalError,
			ErrStr:    "fail to converse []byte to KeyGenDetail",
			RequestID: requestID,
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}

	rawExtraInfo := KeySignExtraInfo{}
	if err := json.Unmarshal([]byte(extraInfo), &rawExtraInfo); err != nil {
		rsp := CallBackResponse{
			Status:    StatusInternalError,
			ErrStr:    "fail to converse []byte to KeySignMeta",
			RequestID: requestID,
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}

	// risk control logical
	if strings.Trim(rawExtraInfo.ToAddress, " ") == "" {
		rsp := CallBackResponse{
			Action:    "REJECT",
			RequestID: requestID,
			Status:    StatusOK,
			ErrStr:    "The target receiver address is empty",
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}

	rcs.RcvWhiteListLock.Lock()
	defer rcs.RcvWhiteListLock.Unlock()
	if _, ok := rcs.RcvWhiteList[rawExtraInfo.ToAddress]; !ok {
		rsp := CallBackResponse{
			Action:    "REJECT",
			RequestID: requestID,
			Status:    StatusOK,
			ErrStr:    "The target receiver address is not in whitelist",
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}

	rsp := CallBackResponse{
		Action:    "APPROVE",
		RequestID: requestID,
		Status:    StatusOK,
	}

	rcs.SendResponse(c, rsp)
}

func (rcs *CallBackService) processKeyReShareRequest(c *gin.Context, rawRequest, extraInfo, requestID string) {
	krDetail := KeyReshareDetail{}
	if err := json.Unmarshal([]byte(rawRequest), &krDetail); err != nil {
		rsp := CallBackResponse{
			Status:    StatusInternalError,
			ErrStr:    "fail to converse []byte to KeyGenDetail",
			RequestID: requestID,
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}

	rawExtraInfo := KeyReshareExtraInfo{}
	if err := json.Unmarshal([]byte(extraInfo), &rawExtraInfo); err != nil {
		rsp := CallBackResponse{
			Status:    StatusInternalError,
			ErrStr:    "fail to converse []byte to KeyReshareMeta",
			RequestID: requestID,
		}
		rcs.SendResponse(c, rsp)
		c.Abort()

		return
	}
	// risk control logical

	rsp := CallBackResponse{
		Action:    "APPROVE",
		RequestID: requestID,
		Status:    StatusOK,
	}

	rcs.SendResponse(c, rsp)
}

func (rcs *CallBackService) GetRawRequest(c *gin.Context) (*CallBackRequest, error) {
	data, exist := c.Get("request")
	if !exist {
		return nil, errors.New("request field not exist")
	}

	byteData, ok := data.([]byte)
	if !ok {
		return nil, errors.New("request data is not []byte type")
	}

	var claim PackageDataClaim
	if err := json.Unmarshal(byteData, &claim); err != nil {
		return nil, err
	}

	req := CallBackRequest{}
	if err := json.Unmarshal(claim.PackageData, &req); err != nil {
		return nil, err
	}

	return &req, nil
}

// ============================== HELP FUNCTION ===========================

func (rcs *CallBackService) ExtractToken(c *gin.Context) string {
	bearToken := c.PostForm("TSS_JWT_MSG")
	return strings.Trim(bearToken, " ")
}

func (rcs *CallBackService) VerifyToken(c *gin.Context) (*jwt.Token, error) {
	tokenString := rcs.ExtractToken(c)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Make sure that the token method conform to "SigningMethodRSA"
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rcs.CallBackPublicKey, nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (rcs *CallBackService) TokenValid(c *gin.Context) error {
	token, err := rcs.VerifyToken(c)
	if err != nil {
		return err
	}

	if token.Valid {
		data, err := json.Marshal(token.Claims)
		if err != nil {
			return errors.New("fail to convert token.Claims to []byte")
		}

		c.Set("request", data)
		return nil
	}

	return errors.New("invalid token")
}

func (rcs *CallBackService) jwtAuthMiddleware() func(c *gin.Context) {
	return func(c *gin.Context) {
		err := rcs.TokenValid(c)
		if err != nil {
			rsp := CallBackResponse{
				Status: StatusInvalidToken,
				ErrStr: err.Error(),
			}
			rcs.SendResponse(c, rsp)
			c.Abort()

			return
		}

		c.Next()
	}
}

func (rcs *CallBackService) SendResponse(c *gin.Context, rsp CallBackResponse) {
	data, err := json.Marshal(rsp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		c.Abort()

		return
	}

	token, err := rcs.CreateToken(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		c.Abort()

		return
	}

	c.JSON(http.StatusOK, token)
}

func (rcs *CallBackService) CreateToken(data []byte) (string, error) {
	// 在这里声明令牌的到期时间
	expirationTime := time.Now().Add(rcs.tokenExpireTime)

	// 创建JWT声明，其中包括有效时间
	claims := &PackageDataClaim{
		PackageData: data,
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    rcs.config.ServiceName,
		},
	}

	// 使用用于签名的算法和令牌
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// 创建JWT字符串
	return token.SignedString(rcs.CallBackHandlerPrivateKey)
}
