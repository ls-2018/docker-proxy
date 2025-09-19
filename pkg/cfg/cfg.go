package cfg

import "strings"

type Options struct {
	Dest       string
	Domains    string
	DomainList []string
	Port       uint64
	PinPath    string
}

func (o *Options) Apply() {
	o.DomainList = strings.Split(o.Domains, ",")
}
