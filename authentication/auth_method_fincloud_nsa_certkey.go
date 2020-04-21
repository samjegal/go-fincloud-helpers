package authentication

import (
	"fmt"
	"log"
	"time"

	"github.com/Azure/go-autorest/autorest"
	"github.com/samjegal/go-fincloud-helpers/fincloud"
	"github.com/samjegal/go-fincloud-helpers/webdriver"
)

type serviceNsaCertkeyAuth struct {
	Subaccount string
	Username   string
	Password   string
}

func (s serviceNsaCertkeyAuth) build(b Builder) (authMethod, error) {
	method := serviceNsaCertkeyAuth{
		Subaccount: b.Subaccount,
		Username:   b.Username,
		Password:   b.Password,
	}
	return method, nil
}

func (s serviceNsaCertkeyAuth) isApplicable(b Builder) bool {
	return b.Subaccount != "" && b.Username != ""
}

func (s serviceNsaCertkeyAuth) getAuthorizationToken(sender autorest.Sender, endpoint string) (autorest.Authorizer, error) {
	// TODO: ENV 환경변수값으로 읽을 수가 있어야 한다.
	config := fincloud.Config{
		Path: "/Users/samjegal/.fincloud/fincloud-certs.yml",
	}

	certdata, err := config.Parse()
	if err != nil {
		return nil, fmt.Errorf("Error parsing fincloud certificate: %v", err)
	}

	var createdYmdt string
	var certKey string
	for _, cert := range certdata.CertificateList {
		if cert.SubaccountName == s.Subaccount {
			createdYmdt = cert.CreateYmdt
			certKey = cert.Key
			break
		}
	}

	timeFormat := "2006-01-02 15:04:05 MST"
	t, err := time.Parse(timeFormat, createdYmdt)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	duration := time.Since(t)
	if duration.Hours() > 6 || certKey == "" {
		builder := &webdriver.Builder{
			Subaccount: s.Subaccount,
			Username:   s.Username,
			Password:   s.Password,

			// 설정파일 정보 및 파싱 데이터
			Config:     &config,
			ConfigData: certdata,
		}

		err = builder.Build()
		if err != nil {
			return nil, err
		}

		err = config.Write(certdata)
		if err != nil {
			return nil, err
		}
	}

	key := ""
	for _, cert := range certdata.CertificateList {
		if cert.SubaccountName == s.Subaccount {
			key = cert.Key
			break
		}
	}

	headers := make(map[string]interface{})
	cookies := "ncp_lang=ko-KR; ncp_locale=ko_KR; ncp_version=v2; ncp_region=FKR; ncp=" + key
	headers["Cookie"] = cookies

	auth := autorest.NewAPIKeyAuthorizer(headers, nil)
	return auth, nil
}

func (s serviceNsaCertkeyAuth) name() string {
	return "Service Account Username Certificate"
}
