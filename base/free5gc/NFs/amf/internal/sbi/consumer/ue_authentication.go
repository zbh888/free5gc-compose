package consumer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"net/url"
	"strconv"

	"github.com/antihax/optional"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nausf_UEAuthentication"
	"github.com/free5gc/openapi/models"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	guard "github.com/zbh888/free5gc-compose/contracts/testcontracts/guardtest"
)

// Recover function takes the message and the signature and returns the address
func Recover(message string, signature string) string {
	data := []byte(message)
	hash := crypto.Keccak256Hash(data)
	sig, err := hexutil.Decode(signature)
	if err != nil {
		log.Fatal(err)
	}
	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		log.Fatal(err)
	}
	return crypto.PubkeyToAddress(*sigPublicKeyECDSA).Hex()
}

func SendUEAuthenticationAuthenticateRequest(ue *amf_context.AmfUe,
	resynchronizationInfo *models.ResynchronizationInfo,
) (*models.UeAuthenticationCtx, *models.ProblemDetails, error) {
	ue.GmmLog.Infof("++++++BOHAN: Forward SUCI to AUSF")
	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(ue.AusfUri)

	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	amfSelf := amf_context.GetSelf()
	servedGuami := amfSelf.ServedGuamiList[0]

	var authInfo models.AuthenticationInfo
	authInfo.SupiOrSuci = ue.Suci
	if mnc, err := strconv.Atoi(servedGuami.PlmnId.Mnc); err != nil {
		return nil, nil, err
	} else {
		authInfo.ServingNetworkName = fmt.Sprintf("5G:mnc%03d.mcc%s.3gppnetwork.org", mnc, servedGuami.PlmnId.Mcc)
	}
	if resynchronizationInfo != nil {
		authInfo.ResynchronizationInfo = resynchronizationInfo
	}

	//=======================================BOHAN ADDED CODE============================================
	banList := map[string]bool{
		"suci-0-208-93-0000-0-0-0000000001": true,
	}

	clientt, err := ethclient.Dial("http://10.100.200.1:7545")
	if err != nil {
		log.Fatal(err)
	}

	address := common.HexToAddress("0x20BF28fa62fF5817D1D6209487d03Dc8d6c7EF11")
	instance, err := guard.NewGuardtest(address, clientt)
	if err != nil {
		log.Fatal(err)
	}
	UDMstat, err := instance.GetUDMStatus(nil)
	if err != nil {
		log.Fatal(err)
	}
	ue.GmmLog.Infof("++++++BOHAN: UDM status %v", UDMstat)
	if banList[ue.Suci] {
		ue.GmmLog.Infof("++++++BOHAN: This BCHERE SUCI %s has been banned", ue.Suci)
		return nil, nil, errors.New("Registration Storm Reject")
	}

	//=======================================BOHAN ENDED HERE=============================================

	ueAuthenticationCtx, httpResponse, err := client.DefaultApi.UeAuthenticationsPost(context.Background(), authInfo)
	defer func() {
		if httpResponse != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("UeAuthenticationsPost response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if err == nil {
		return &ueAuthenticationCtx, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return nil, &problem, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func SendAuth5gAkaConfirmRequest(ue *amf_context.AmfUe, resStar string) (
	*models.ConfirmationDataResponse, *models.ProblemDetails, error,
) {
	var ausfUri string
	if confirmUri, err := url.Parse(ue.AuthenticationCtx.Links["5g-aka"].Href); err != nil {
		return nil, nil, err
	} else {
		ausfUri = fmt.Sprintf("%s://%s", confirmUri.Scheme, confirmUri.Host)
	}

	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(ausfUri)
	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	confirmData := &Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutParamOpts{
		ConfirmationData: optional.NewInterface(models.ConfirmationData{
			ResStar: resStar,
		}),
	}

	confirmResult, httpResponse, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(
		context.Background(), ue.Suci, confirmData)
	defer func() {
		if httpResponse != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("UeAuthenticationsAuthCtxId5gAkaConfirmationPut response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if err == nil {
		return &confirmResult, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		switch httpResponse.StatusCode {
		case 400, 500:
			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func SendEapAuthConfirmRequest(ue *amf_context.AmfUe, eapMsg nasType.EAPMessage) (
	response *models.EapSession, problemDetails *models.ProblemDetails, err1 error,
) {
	confirmUri, err := url.Parse(ue.AuthenticationCtx.Links["eap-session"].Href)
	if err != nil {
		logger.ConsumerLog.Errorf("url Parse failed: %+v", err)
	}
	ausfUri := fmt.Sprintf("%s://%s", confirmUri.Scheme, confirmUri.Host)

	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(ausfUri)
	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	eapSessionReq := &Nausf_UEAuthentication.EapAuthMethodParamOpts{
		EapSession: optional.NewInterface(models.EapSession{
			EapPayload: base64.StdEncoding.EncodeToString(eapMsg.GetEAPMessage()),
		}),
	}

	eapSession, httpResponse, err := client.DefaultApi.EapAuthMethod(context.Background(), ue.Suci, eapSessionReq)
	defer func() {
		if httpResponse != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("EapAuthMethod response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if err == nil {
		response = &eapSession
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			err1 = err
			return
		}
		switch httpResponse.StatusCode {
		case 400, 500:
			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			problemDetails = &problem
		}
	} else {
		err1 = openapi.ReportError("server no response")
	}

	return response, problemDetails, err1
}
