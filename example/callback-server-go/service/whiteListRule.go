package service

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

type AddressWhitelistRequest struct {
	Address string `json:"address"`
}

type AddressWhitelistResponse struct {
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
}

type ListAddressWhitelistResponse struct {
	AddressList []string `json:"address_list"`
}

func (rcs *CallBackService) AddReceiverAddress(c *gin.Context) {
	req := AddressWhitelistRequest{}
	rsp := AddressWhitelistResponse{}

	err := c.BindJSON(&req)
	if err != nil {
		rsp.Status = 400
		rsp.Error = err.Error()
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	if strings.Trim(req.Address, " ") == "" {
		rsp.Status = 400
		rsp.Error = "Receiver address should not be empty"
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	if !IsValidEthAddress(req.Address) && !IsValidBtcAddress(req.Address) {
		rsp.Status = 400
		rsp.Error = "Receiver address is not valid btc or eth address"
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	rcs.RcvWhiteListLock.Lock()
	rcs.RcvWhiteList[req.Address] = true
	rcs.RcvWhiteListLock.Unlock()

	rsp.Status = 200
	c.JSON(http.StatusOK, rsp)
}

func (rcs *CallBackService) RemoveReceiverAddress(c *gin.Context) {
	req := AddressWhitelistRequest{}
	rsp := AddressWhitelistResponse{}

	err := c.BindJSON(&req)
	if err != nil {
		rsp.Status = 400
		rsp.Error = err.Error()
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	if strings.Trim(req.Address, " ") == "" {
		rsp.Status = 400
		rsp.Error = "Receiver address should not be empty"
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	rcs.RcvWhiteListLock.Lock()
	delete(rcs.RcvWhiteList, req.Address)
	rcs.RcvWhiteListLock.Unlock()

	rsp.Status = 200
	c.JSON(http.StatusOK, rsp)
}

func (rcs *CallBackService) ListReceiverAddress(c *gin.Context) {
	rcs.RcvWhiteListLock.Lock()
	defer rcs.RcvWhiteListLock.Unlock()

	rsp := ListAddressWhitelistResponse{}
	rst := make([]string, 0)
	for addr, _ := range rcs.RcvWhiteList {
		rst = append(rst, addr)
	}
	rsp.AddressList = rst

	c.JSON(http.StatusOK, rsp)
}

func IsValidEthAddress(address string) bool {
	re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
	return re.MatchString(address)
}

func IsValidBtcAddress(address string) bool {
	Addrlen := len(address)
	if Addrlen < 25 {
		return false
	}

	if strings.HasPrefix(address, "1") {
		if Addrlen >= 26 && Addrlen <= 34 {
			return true
		}
	}

	if strings.HasPrefix(address, "3") && Addrlen == 34 {
		return true
	}

	if strings.HasPrefix(address, "bc1") && Addrlen > 34 {
		return true
	}

	return false
}
