// Package web embeds the static assets of the hub UI.
//
// Shipping the interface inside the binary keeps the container to a single
// artifact: no volume, no asset pipeline and no CDN to reach from an isolated
// network.
package web

import "embed"

// Assets holds the served files under public/.
//
//go:embed public
var Assets embed.FS
