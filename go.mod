module golang.zx2c4.com/wireguard/windows

go 1.15

require (
	github.com/lxn/walk v0.0.0-20201104150514-d863433c8048
	github.com/lxn/win v0.0.0-20201105135849-85a11ff06ebc
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20201031054903-ff519b6c9102
	golang.org/x/sys v0.0.0-20201107080550-4d91cf3a1aaf
	golang.org/x/text v0.3.4
	golang.zx2c4.com/wireguard v0.0.20200321-0.20201107205632-82128c47d90a
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20201107182838-3335d2bb3fc1
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20201107183008-659a4e955570
)
