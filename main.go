// dig_rr_test project main.go
package main

import (
	"fmt"
	"time"
)

func main() {
	remsg, err := send("d.root-servers.net.", "gdh91.com", 2, 3*time.Second)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(remsg)
	for _, v := range remsg.Answer {
		if soa, ok := v.(*SOA); ok {
			fmt.Println("SOA:", soa.Ns)
		}
	}
	for _, v := range remsg.Ns {
		if ns, ok := v.(*NS); ok {
			fmt.Println("NAME:", ns.Ns)
		}
	}
	for _, v := range remsg.Extra {
		if cn, ok := v.(*CNAME); ok {
			fmt.Println("CNAME:", cn.Target)
		}
	}
	for _, v := range remsg.Answer {
		if a, ok := v.(*A); ok {
			fmt.Println("A:", a.A.String())
		}
	}
	for _, v := range remsg.Answer {
		if m, ok := v.(*MX); ok {
			fmt.Println("MX:", m.Mx)
		}
	}
	for _, v := range remsg.Answer {
		if t, ok := v.(*TXT); ok {
			fmt.Println("TXT:", t.TXT)
		}
	}

}
