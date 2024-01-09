package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// IsPEMCertificateExpired check if a pem certificate expired
func IsPEMCertificateExpired(logger *logrus.Entry, encodedCert, certName string, expirationTime time.Time) (bool, error) {
	if encodedCert == "" {
		logger.Errorf("cert is empty")
		return false, fmt.Errorf("empty cert of %s", certName)
	}

	block, leftover := pem.Decode([]byte(encodedCert))
	if len(leftover) > 0 {
		logger.Warningf("leftover string in cert of %s", certName)
	}

	if block == nil || len(block.Bytes) < 1 {
		return false, fmt.Errorf("failed to pem decode cert of %s", certName)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse cert of %s, error: %s", certName, err)
	}

	logger.Infof("cert.NotAfter: %s", cert.NotAfter.String())
	if cert.NotAfter.Before(expirationTime) {
		return true, nil
	}

	return false, nil
}
