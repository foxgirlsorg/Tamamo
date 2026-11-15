// Package app is the tamamo program: a reverse proxy that asks browsers for a
// small SHA-256 proof of work before letting them through, and blocks known
// scrapers.
//
// It is a package rather than a main function so that a build with extra
// modules is three lines: import this package, blank-import the modules and
// call Main. That is what tamamo-build generates:
//
//	package main
//
//	import (
//		"github.com/foxgirlsorg/tamamo/app"
//
//		_ "github.com/you/tamamo-geo"
//	)
//
//	func main() { app.Main() }
package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/foxgirlsorg/tamamo/internal/admin"
	"github.com/foxgirlsorg/tamamo/internal/assets"
	"github.com/foxgirlsorg/tamamo/internal/config"
	"github.com/foxgirlsorg/tamamo/internal/server"
	"github.com/foxgirlsorg/tamamo/internal/stats"
	"github.com/foxgirlsorg/tamamo/module"
)

// Version is the release version, reported by -version and the admin API.
const Version = "0.2.0"

// Main runs tamamo with the command line of the process and exits when it
// is done.
func Main() {
	defData := os.Getenv("TAMAMO_DATA")
	if defData == "" {
		defData = "./data"
	}
	dataDir := flag.String("data", defData, "directory for tamamo.yaml, secret.key, tamamo.db and uploads (env TAMAMO_DATA)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	healthcheck := flag.Bool("healthcheck", false, "check that a running Tamamo answers on its listen address, exit 0 if healthy")
	check := flag.Bool("check", false, "validate tamamo.yaml without starting, exit 0 if it is fine")
	setLogin := flag.String("set-login", "", "set the admin `username`; the password is read from TAMAMO_ADMIN_PASSWORD or the first line of stdin")
	rotateSecret := flag.Bool("rotate-secret", false, "replace the signing secret (signs every visitor out) and exit")
	listModules := flag.Bool("modules", false, "list the modules compiled into this build and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("tamamo", Version)
		return
	}
	if *listModules {
		printModules()
		return
	}
	if *healthcheck {
		os.Exit(runHealthcheck(*dataDir))
	}
	if *check || *setLogin != "" || *rotateSecret {
		if err := runCommand(*dataDir, *check, *setLogin, *rotateSecret); err != nil {
			fmt.Fprintln(os.Stderr, "tamamo:", err)
			os.Exit(1)
		}
		return
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err := run(*dataDir); err != nil {
		slog.Error("tamamo stopped", "err", err)
		os.Exit(1)
	}
}

func run(dataDir string) error {
	mgr, err := config.Load(dataDir)
	if err != nil {
		return err
	}
	if err := applyEnvLogin(mgr); err != nil {
		return err
	}
	as, err := assets.New(dataDir)
	if err != nil {
		return fmt.Errorf("image store: %w", err)
	}
	st, err := stats.New(dataDir, mgr)
	if err != nil {
		return fmt.Errorf("stats: %w", err)
	}
	defer st.Close()
	// Statistics are kept per site ID, which follows the site's name.
	mgr.OnSiteRename(st.RenameSites)
	cfg := mgr.Get()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Pick up edits to tamamo.yaml made on disk.
	go mgr.Watch(ctx)

	statsCtx, stopStats := context.WithCancel(context.Background())
	statsDone := make(chan struct{})
	go func() {
		st.Run(statsCtx)
		close(statsDone)
	}()

	errc := make(chan error, 2)

	handler := server.New(mgr, st, as)
	defer handler.Close() // stops the modules' background work
	mainSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		// No WriteTimeout: proxied responses may stream for a long time.
	}
	go func() {
		if err := mainSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("listening on %s: %w", cfg.Server.Listen, err)
		}
	}()
	slog.Info("tamamo is protecting your site", "version", Version, "url", displayURL(cfg.Server.Listen), "upstream", cfg.Server.Target, "data", dataDir)
	if mods := module.Registered(); len(mods) > 0 {
		ids := make([]string, len(mods))
		for i, m := range mods {
			ids[i] = m.ID
		}
		slog.Info("modules in this build", "modules", strings.Join(ids, ", "), "running", len(handler.Modules().Instances()))
	}

	var adminSrv *http.Server
	var adminOnce sync.Once
	shutdownAdmin := func() {
		adminOnce.Do(func() {
			if adminSrv == nil {
				return
			}
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = adminSrv.Shutdown(sctx)
		})
	}
	if cfg.Admin.Enabled {
		adminSrv = &http.Server{
			Addr: cfg.Admin.Listen,
			Handler: admin.New(admin.Options{
				Config:             mgr,
				Stats:              st,
				Assets:             as,
				Modules:            handler.Modules(),
				Version:            Version,
				RunningListen:      cfg.Server.Listen,
				RunningAdminListen: cfg.Admin.Listen,
			}),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       time.Minute,
			WriteTimeout:      time.Minute,
			IdleTimeout:       2 * time.Minute,
		}
		srv := adminSrv
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("admin API on %s: %w", cfg.Admin.Listen, err)
			}
		}()
		slog.Info("admin API is listening (the optional web UI container connects here)", "url", displayURL(cfg.Admin.Listen))
		if cfg.Admin.Username == "" || cfg.Admin.PasswordHash == "" {
			slog.Warn("************************************************************")
			slog.Warn("No admin login is set up yet. The FIRST person to open the web UI will be asked to create it.",
				"url", displayURL(cfg.Admin.Listen))
			slog.Warn("Open it now, or set it with TAMAMO_ADMIN_USERNAME / TAMAMO_ADMIN_PASSWORD or `tamamo -set-login <username>`.")
			slog.Warn("************************************************************")
		}
	} else {
		slog.Info("admin API is off; start with TAMAMO_ENABLE_API=true to use the web UI")
	}

	var runErr error
	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case runErr = <-errc:
	}

	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := mainSrv.Shutdown(sctx); err != nil {
		slog.Warn("main server did not shut down cleanly", "err", err)
	}
	shutdownAdmin()
	stopStats()
	<-statsDone
	return runErr
}

// runCommand runs the one-shot command-line actions. A running Tamamo
// picks up their changes to tamamo.yaml within a few seconds.
func runCommand(dataDir string, check bool, login string, rotate bool) error {
	if check {
		if err := config.Check(dataDir); err != nil {
			return err
		}
		fmt.Println(filepath.Join(dataDir, config.FileName), "is valid")
		if login == "" && !rotate {
			return nil
		}
	}
	mgr, err := config.Load(dataDir)
	if err != nil {
		return err
	}
	if login != "" {
		pw := os.Getenv("TAMAMO_ADMIN_PASSWORD")
		if pw == "" {
			fmt.Fprint(os.Stderr, "new admin password: ")
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil && line == "" {
				return fmt.Errorf("reading the password from stdin: %w", err)
			}
			pw = strings.TrimRight(line, "\r\n")
		}
		if err := setAdminLogin(mgr, login, pw); err != nil {
			return err
		}
		fmt.Println("admin login saved for", login)
	}
	if rotate {
		if err := mgr.RotateSecret(); err != nil {
			return err
		}
		fmt.Println("signing secret replaced; every visitor has to pass the check again")
	}
	return nil
}

// applyEnvLogin sets the admin login from TAMAMO_ADMIN_USERNAME and
// TAMAMO_ADMIN_PASSWORD when both are set. The stored hash is only replaced
// when the login actually changed.
func applyEnvLogin(mgr *config.Manager) error {
	user, pw := os.Getenv("TAMAMO_ADMIN_USERNAME"), os.Getenv("TAMAMO_ADMIN_PASSWORD")
	if user == "" && pw == "" {
		return nil
	}
	if user == "" || pw == "" {
		return errors.New("set both TAMAMO_ADMIN_USERNAME and TAMAMO_ADMIN_PASSWORD, or neither")
	}
	st := mgr.Stored()
	if st.Admin.Username == user && admin.VerifyPassword(st.Admin.PasswordHash, pw) {
		return nil
	}
	if err := setAdminLogin(mgr, user, pw); err != nil {
		return fmt.Errorf("TAMAMO_ADMIN_USERNAME / TAMAMO_ADMIN_PASSWORD: %w", err)
	}
	slog.Info("admin login set from the environment", "username", user)
	return nil
}

func setAdminLogin(mgr *config.Manager, user, pw string) error {
	if err := admin.ValidateCredentials(user, pw); err != nil {
		return err
	}
	hash, err := admin.HashPassword(pw)
	if err != nil {
		return err
	}
	return mgr.Update(func(c *config.Config) error {
		c.Admin.Username = user
		c.Admin.PasswordHash = hash
		return nil
	})
}

// displayURL turns a listen address like ":8923" into a clickable URL.
func displayURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// runHealthcheck asks the running instance for /.tamamo/health. It does not
// load the config through the manager (which would rewrite the file); it
// only reads the listen address. Returns the process exit code.
func runHealthcheck(dataDir string) int {
	listen := os.Getenv("TAMAMO_LISTEN")
	if listen == "" {
		if b, err := os.ReadFile(filepath.Join(dataDir, config.FileName)); err == nil {
			if c, err := config.ParseConfigYAML(b); err == nil {
				listen = c.Server.Listen
			}
		}
	}
	if listen == "" {
		listen = ":8923"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: bad listen address:", listen)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" || strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + server.HealthURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.Status)
		return 1
	}
	return 0
}

// printModules lists the modules compiled into this build, with the Go
// module each one came from when the build recorded it.
func printModules() {
	mods := module.Registered()
	if len(mods) == 0 {
		fmt.Println("This build contains no modules. Add some with tamamo-build --with <go module>.")
		return
	}
	for _, m := range mods {
		line := m.ID
		if m.Version != "" {
			line += " " + m.Version
		}
		if m.Name != m.ID {
			line += "  (" + m.Name + ")"
		}
		fmt.Println(line)
		if m.Description != "" {
			fmt.Println("    " + m.Description)
		}
		for _, f := range m.Settings {
			req := ""
			if f.Required {
				req = ", required"
			}
			def := ""
			if f.Default != "" {
				def = ", default " + f.Default
			}
			fmt.Printf("    - %s (%s%s%s) %s\n", f.Name, f.Type, req, def, f.Description)
		}
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		fmt.Println()
		fmt.Println("Go modules linked into this binary:")
		for _, d := range bi.Deps {
			if d.Replace != nil {
				fmt.Printf("    %s %s => %s\n", d.Path, d.Version, d.Replace.Path)
			} else {
				fmt.Printf("    %s %s\n", d.Path, d.Version)
			}
		}
	}
}
