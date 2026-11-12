package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"proxy.local/m0/internal/capture"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/core"
	"proxy.local/m0/internal/dnsengine"
	"proxy.local/m0/internal/ipc"
	"proxy.local/m0/internal/logbuffer"
	"proxy.local/m0/internal/servicehost"
	"proxy.local/m0/internal/windivert"
)

func Run(args []string, out io.Writer) error {
	service := false
	if len(args) > 0 && args[0] == "--service-run" {
		service = true
		args = args[1:]
	}
	if len(args) == 2 && args[0] == "--capture-guard" {
		return capture.RunGuard(args[1])
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	directory := filepath.Join(cache, "proxy-m1")
	if runtime.GOOS == "linux" {
		directory = "/var/lib/proxyd"
	}
	home, _ := os.UserHomeDir()
	regular := func(path string) bool {
		info, err := os.Stat(path)
		return err == nil && info.Mode().IsRegular()
	}
	configPath := defaultConfigPath(runtime.GOOS, home, regular)
	if runtime.GOOS != "linux" && filepath.IsAbs(configPath) {
		directory = filepath.Join(home, ".proxy", "runtime")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	run := func(cmd *cobra.Command, _ []string) error {
		if service {
			return servicehost.Run(cmd.Context(), configPath, directory)
		}
		return core.Serve(cmd.Context(), configPath, directory)
	}
	root := &cobra.Command{Use: "proxy", SilenceUsage: true, SilenceErrors: true}
	if service {
		root.Args = cobra.NoArgs
		root.RunE = run
	}
	root.SetOut(out)
	root.SetArgs(args)
	root.PersistentFlags().StringVar(&directory, "runtime", directory, "private runtime directory or pipe instance")
	root.PersistentFlags().StringVar(&configPath, "config", configPath, "YAML configuration path")
	if !service {
		var pathAction, pathDirectory string
		installerPath := &cobra.Command{Use: "installer-path", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return servicehost.InstallerPath(pathAction, pathDirectory)
		}}
		installerPath.Flags().StringVar(&pathAction, "action", "", "add or remove")
		installerPath.Flags().StringVar(&pathDirectory, "directory", "", "absolute installation directory")
		root.AddCommand(installerPath)
		captureCmd := &cobra.Command{Use: "capture"}
		var captureJSON bool
		captureStatus := &cobra.Command{
			Use: "status", Short: "Inspect an existing WinDivert runtime without installing the driver",
			Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				status, inspectErr := windivert.Inspect()
				report := struct {
					windivert.Status
					Error string `json:"error,omitempty"`
				}{Status: status}
				if inspectErr != nil {
					report.Error = inspectErr.Error()
				}
				encoder := json.NewEncoder(cmd.OutOrStdout())
				if !captureJSON {
					encoder.SetIndent("", "  ")
				}
				if err := encoder.Encode(report); err != nil {
					return err
				}
				return inspectErr
			},
		}
		captureStatus.Flags().BoolVar(&captureJSON, "json", false, "emit compact JSON")
		captureCmd.AddCommand(captureStatus)
		var sniffFilter string
		var sniffDuration time.Duration
		sniffCmd := &cobra.Command{
			Use: "sniff", Short: "Count copied packets for a limited time (may load the signed WinDivert driver)",
			Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if sniffDuration <= 0 || sniffDuration > time.Minute {
					return fmt.Errorf("--duration must be greater than zero and at most one minute")
				}
				ctx, stop := context.WithTimeout(cmd.Context(), sniffDuration)
				defer stop()
				counts, err := windivert.Sniff(ctx, sniffFilter, func() {
					fmt.Fprintln(cmd.ErrOrStderr(), "WinDivert sniff ready")
				})
				if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(counts); encodeErr != nil {
					return encodeErr
				}
				return err
			},
		}
		sniffCmd.Flags().StringVar(&sniffFilter, "filter", "loopback and (tcp or udp)", "WinDivert NETWORK layer filter")
		sniffCmd.Flags().DurationVar(&sniffDuration, "duration", 10*time.Second, "capture duration, at most one minute")
		captureCmd.AddCommand(sniffCmd)
		root.AddCommand(captureCmd)
		root.AddCommand(&cobra.Command{Use: "run", Short: "Run in the foreground", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "linux" && !cmd.Flags().Changed("config") {
				configPath = defaultConfigPath("foreground", home, regular)
			}
			return run(cmd, args)
		}})
		control := func(operation string) func(*cobra.Command, []string) error {
			return func(cmd *cobra.Command, _ []string) error {
				ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
				defer cancel()
				return servicehost.SimpleControl(ctx, operation, configPath, directory)
			}
		}
		startRun := run
		if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
			startRun = control("start")
		}
		root.AddCommand(&cobra.Command{Use: "start", Short: "Start the proxy", Args: cobra.NoArgs, RunE: startRun})
		root.AddCommand(&cobra.Command{Use: "restart", Short: "Restart the proxy", Args: cobra.NoArgs, RunE: control("restart")})
		configCmd := &cobra.Command{Use: "config"}
		configCmd.AddCommand(&cobra.Command{Use: "check", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if err := core.Check(configPath); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "configuration OK")
			return nil
		}})
		root.AddCommand(configCmd)
		root.AddCommand(&cobra.Command{Use: "version", Args: cobra.NoArgs, Run: func(cmd *cobra.Command, _ []string) { fmt.Fprintln(cmd.OutOrStdout(), core.Version) }})
		root.AddCommand(&cobra.Command{Use: "capture-cleanup", Short: "Remove owned stale capture in the same namespace", Args: cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error { return capture.Cleanup(directory) }})
		request := func(label, command string) *cobra.Command {
			var compact bool
			cmd := &cobra.Command{Use: label, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
				path, err := filepath.Abs(directory)
				if err != nil {
					return err
				}
				timeout := 15 * time.Second
				if command == "geo-update" {
					timeout = time.Minute
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
				defer cancel()
				result, err := ipc.Call(ctx, path, command)
				if err != nil {
					return err
				}
				if compact {
					fmt.Fprintln(cmd.OutOrStdout(), string(result))
					return nil
				}
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}}
			cmd.Flags().BoolVar(&compact, "json", false, "emit compact JSON")
			return cmd
		}
		stop := request("stop", "stop")
		stopRequest := stop.RunE
		if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
			stop.RunE = func(cmd *cobra.Command, args []string) error {
				if cmd.Flags().Changed("runtime") {
					return stopRequest(cmd, args)
				}
				return control("stop")(cmd, args)
			}
		}
		root.AddCommand(request("status", "status"), request("reload", "reload"), stop)
		webCmd := &cobra.Command{
			Use:   "web",
			Short: "Display the web dashboard address",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				cfg, err := config.Load(configPath)
				if err != nil {
					return err
				}
				addr := "127.0.0.1:9100"
				if cfg.Web.Listen != "" {
					addr = cfg.Web.Listen
				}
				fmt.Fprintf(cmd.OutOrStdout(), "http://%s\n", addr)
				return nil
			},
		}
		root.AddCommand(webCmd)
		var follow bool
		logs := &cobra.Command{Use: "logs", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := filepath.Abs(directory)
			if err != nil {
				return err
			}
			var after uint64
			for {
				ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				data, err := ipc.Call(ctx, path, fmt.Sprintf("logs:%d", after))
				cancel()
				if err != nil {
					return err
				}
				var snapshot logbuffer.Snapshot
				if err := json.Unmarshal(data, &snapshot); err != nil {
					return err
				}
				for _, entry := range snapshot.Entries {
					fmt.Fprintln(cmd.OutOrStdout(), entry.Text)
				}
				after = snapshot.Next
				if !follow {
					return nil
				}
				select {
				case <-cmd.Context().Done():
					return nil
				case <-time.After(time.Second):
				}
			}
		}}
		logs.Flags().BoolVarP(&follow, "follow", "f", false, "follow recent in-memory logs")
		root.AddCommand(logs)
		connections := &cobra.Command{Use: "connections"}
		connections.AddCommand(request("list", "connections"))
		root.AddCommand(connections)
		dnsCmd := &cobra.Command{Use: "dns"}
		dnsCmd.AddCommand(request("status", "dns-status"), request("flush", "dns-flush"))
		var qtype string
		var server string
		var tcp bool
		probe := &cobra.Command{Use: "test NAME", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			var address netip.AddrPort
			timeout := 4 * time.Second
			if server == "" {
				cfg, err := config.Load(configPath)
				if err != nil {
					return err
				}
				if !cfg.DNS.Enabled || len(cfg.DNS.Listen) == 0 {
					return fmt.Errorf("no standalone DNS listener; specify --server")
				}
				address, timeout = cfg.DNS.Listen[0], 2*cfg.DNS.Timeout+time.Second
			} else {
				var err error
				address, err = netip.ParseAddrPort(server)
				if err != nil || address.Port() == 0 {
					return fmt.Errorf("--server requires a numeric IP and port")
				}
			}
			kind, ok := dns.StringToType[strings.ToUpper(qtype)]
			if !ok {
				return fmt.Errorf("unknown DNS record type %q", qtype)
			}
			network := "udp"
			if tcp {
				network = "tcp"
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			answer, err := dnsengine.Probe(ctx, address, network, args[0], kind)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), answer)
			return nil
		}}
		probe.Flags().StringVar(&qtype, "type", "A", "DNS record type")
		probe.Flags().BoolVar(&tcp, "tcp", false, "query over TCP")
		probe.Flags().StringVar(&server, "server", "", "explicit DNS server IP:port")
		dnsCmd.AddCommand(probe)
		root.AddCommand(dnsCmd)
		geoCmd := &cobra.Command{Use: "geo"}
		geoCmd.AddCommand(request("status", "geo-status"), request("update", "geo-update"))
		root.AddCommand(geoCmd)
		serviceCmd := &cobra.Command{Use: "service", Hidden: true}
		for _, operation := range []string{"start", "stop", "restart", "status", "enable", "disable"} {
			serviceCmd.AddCommand(&cobra.Command{Use: operation, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
				ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
				defer cancel()
				return servicehost.Control(ctx, operation)
			}})
		}
		var executable string
		install := &cobra.Command{Use: "install", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if executable == "" {
				var err error
				executable, err = os.Executable()
				if err != nil {
					return err
				}
			}
			return servicehost.Install(executable, configPath, directory, false)
		}}
		install.Flags().StringVar(&executable, "binary", "", "service executable (default: this proxy executable)")
		serviceCmd.AddCommand(install, &cobra.Command{Use: "uninstall", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return servicehost.Uninstall() }})
		root.AddCommand(serviceCmd)
	}
	return root.ExecuteContext(ctx)
}
