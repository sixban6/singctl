// 文件职责：嵌入嗅探引擎远端只读采集与最小防火墙表自举 POSIX Shell 脚本。
package sniff

import _ "embed"

//go:embed scripts/harvest.sh
var remoteHarvestScriptBody string

//go:embed scripts/ensure_nft.sh
var remoteEnsureSecurityNFTBlock string
