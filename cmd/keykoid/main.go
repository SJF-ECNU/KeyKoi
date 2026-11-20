// Command keykoid 是 KeyKoi 后台服务入口。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"keykoi/internal/broker"
	"keykoi/internal/central"
	"keykoi/internal/daemon"
	"keykoi/internal/osruntime"
	"keykoi/internal/store"
	"keykoi/internal/vault"
)

func main() {
	var (
		dataDir     = flag.String("data-dir", "", "data directory (default: ~/Library/Application Support/KeyKoi)")
		socket      = flag.String("socket", "", "IPC socket path")
		gateway     = flag.String("gateway", "127.0.0.1:8377", "gateway listen address on loopback")
		userLabel   = flag.String("user-label", "", "display name for the local macOS account")
		adminAddr   = flag.String("admin", "127.0.0.1:8378", "management UI listen address on loopback")
		prototype   = flag.Bool("prototype", false, "run the P0 in-memory prototype backend")
		dbPath      = flag.String("db", "", "SQLite database path (default: <data-dir>/vault.db)")
		adapters    = flag.String("adapters", "", "adapter manifest directory (default: ./adapters)")
		keykoiBin   = flag.String("keykoi-bin", "", "absolute path of the keykoi helper binary")
		centralURL  = flag.String("central", "", "central service URL (multi-device mode)")
		centralBoot = flag.String("central-bootstrap", "", "one-time bootstrap credential for device registration")
		centralMode = flag.String("central-mode", "online", "online | short_term")
		deviceName  = flag.String("device-name", "", "device name shown in the center")
		foreground  = flag.Bool("foreground", true, "run in foreground")
		bioHelper   = flag.String("biometric-helper", "", "path to the macOS biometric helper (default: next to keykoid, or $KEYKOI_BIOMETRIC_HELPER)")
		bioAccount  = flag.String("biometric-account", "", "keychain account for the biometric root key")
		skipBio     = flag.Bool("skip-biometric", false, "disable Touch ID unlock (master password only)")
	)
	flag.Parse()
	_ = foreground

	dir := *dataDir
	if dir == "" {
		dir = osruntime.DefaultDataDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatalf("prepare data dir: %v", err)
	}
	sockPath := *socket
	if sockPath == "" {
		sockPath = osruntime.SocketPath(dir)
	}

	adapterDir := *adapters
	if adapterDir == "" {
		adapterDir = "adapters"
	}
	if abs, err := filepath.Abs(adapterDir); err == nil {
		adapterDir = abs
	}
	binPath := *keykoiBin
	if binPath == "" {
		if exe, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(exe), "keykoi")
			if _, statErr := os.Stat(candidate); statErr == nil {
				binPath = candidate
			}
		}
	}
	brokerOpts := broker.Options{SessionTTL: 12 * time.Hour, MaxLeaseDuration: 10 * time.Minute}
	if *centralURL != "" {
		name := *deviceName
		if name == "" {
			host, _ := os.Hostname()
			name = "keykoi-device-" + host
		}
		cc, err := central.LoadOrRegister(context.Background(), filepath.Join(dir, "device.json"), *centralURL, *centralBoot, name, *centralMode)
		if err != nil {
			log.Fatalf("central device: %v", err)
		}
		brokerOpts.Gate = cc
		log.Printf("keykoid: central mode %s device=%s", cc.Mode, cc.DeviceID)
	}
	bioCfg := daemon.BiometricConfig{Account: *bioAccount}
	if !*skipBio && os.Getenv("KEYKOI_BIOMETRIC_DISABLE") != "1" {
		bioCfg.HelperPath = vault.ResolveHelperPath(*bioHelper)
	}
	cfg := daemon.Config{DataDir: dir, SocketPath: sockPath, GatewayAddr: *gateway, AdminAddr: *adminAddr, UserLabel: *userLabel,
		AdaptersDir: adapterDir, KeyKoiBin: binPath,
		Broker: brokerOpts, Biometric: bioCfg}

	var (
		st store.Store
		be daemon.Backend
		d  *daemon.Daemon
	)
	if *prototype {
		mem := store.NewMemory()
		src := broker.NewMemorySource()
		st = mem
		be = daemon.NewMemoryBackend(mem, src)
		log.Printf("keykoid: prototype backend (no persistence)")
	} else {
		path := *dbPath
		if path == "" {
			path = dir + "/vault.db"
		}
		sqliteStore, err := store.OpenSQLite(path)
		if err != nil {
			log.Fatalf("open vault database: %v", err)
		}
		var biometric vault.BiometricStore
		if bioCfg.HelperPath != "" {
			biometric = vault.NewHelperClient(bioCfg.HelperPath, bioCfg.Account)
			log.Printf("keykoid: Touch ID helper at %s", bioCfg.HelperPath)
		} else {
			log.Printf("keykoid: Touch ID disabled; biometric unlock will report AUTH_UNAVAILABLE")
		}
		v, err := vault.Open(sqliteStore, vault.Options{Biometric: biometric, BiometricAccount: bioCfg.Account})
		if err != nil {
			log.Fatalf("open vault: %v", err)
		}
		st = sqliteStore
		be = v
		log.Printf("keykoid: encrypted vault backend at %s", path)
	}
	d = daemon.New(cfg, st, be)
	if err := d.Start(); err != nil {
		log.Fatalf("start daemon: %v", err)
	}
	log.Printf("keykoid listening: socket=%s gateway=%s admin=%s state=%s", d.SocketPath(), d.GatewayAddr(), d.AdminAddr(), be.State())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("shutting down")
	d.Stop()
	if err := be.Close(); err != nil {
		log.Printf("close backend: %v", err)
	}
}
