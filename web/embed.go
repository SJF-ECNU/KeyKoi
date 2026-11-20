// Package web 以嵌入资源方式提供本机管理界面，二进制单独分发即可使用。
package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html
var assets embed.FS

// FS 返回管理界面静态资源。
func FS() fs.FS { return assets }
