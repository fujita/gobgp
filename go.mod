module github.com/osrg/gobgp/v3

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e
	github.com/dgryski/go-farm v0.0.0-20171119141306-ac7624ea8da3
	github.com/eapache/channels v1.1.0
	github.com/go-test/deep v1.0.6
	github.com/golang/protobuf v1.4.1
	github.com/google/uuid v1.1.1
	github.com/jessevdk/go-flags v1.3.0
	github.com/k-sone/critbitgo v1.3.1-0.20191024122315-48c9e1530131
	github.com/kr/pretty v0.2.0
	github.com/osrg/gobgp v2.0.0+incompatible
	github.com/sirupsen/logrus v0.0.0-20170713114250-a3f95b5c4235
	github.com/spf13/cobra v0.0.0-20170731170427-b26b538f6930
	github.com/spf13/viper v1.0.0
	github.com/stretchr/testify v1.6.0
	github.com/vishvananda/netlink v0.0.0-20170802012344-a95659537721
	golang.org/x/net v0.0.0-20200528225125-3c3fba18258b
	google.golang.org/grpc v1.27.0
)

replace github.com/osrg/gobgp v2.0.0+incompatible => ./

go 1.13
