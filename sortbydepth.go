package x509utils

import (
	"crypto/x509"
	"sort"
)

type certWithParent struct {
	cert   *x509.Certificate
	parent *certWithParent
}

type byDepth []*certWithParent

func (bd byDepth) Len() int           { return len(bd) }
func (bd byDepth) Swap(i, j int)      { bd[i], bd[j] = bd[j], bd[i] }
func (bd byDepth) Less(i, j int) bool { return depth(bd[i]) < depth(bd[j]) }

func depth(cwp *certWithParent) int {
	if cwp.parent == nil {
		return 0
	} else {
		return 1 + depth(cwp.parent)
	}
}

func SortByDepth(certs []*x509.Certificate) {
	cwps := make(byDepth, len(certs))

	for i, cert := range certs {
		cwps[i] = &certWithParent{
			cert:   cert,
			parent: findParent(cert, remove(certs, i)),
		}
	}

	sort.Sort(cwps)

	for i, cwp := range cwps {
		certs[i] = cwp.cert
	}
}

func findParent(cert *x509.Certificate, possibleCAs []*x509.Certificate) *certWithParent {
	for j, possibleCA := range possibleCAs {
		roots := x509.NewCertPool()
		roots.AddCert(possibleCA)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
			return &certWithParent{
				cert:   possibleCA,
				parent: findParent(possibleCA, remove(possibleCAs, j)),
			}
		}
	}

	return nil
}

func remove(certs []*x509.Certificate, i int) []*x509.Certificate {
	result := make([]*x509.Certificate, i)
	copy(result, certs[:i])
	return append(result, certs[i+1:]...)
}
