package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/updater"
)

func newUpdateCommand(configPath *string) *cobra.Command {
	var (
		checkOnly  bool
		version    string
		force      bool
		prerelease bool
		repo       string
		baseURL    string
		asJSON     bool
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check and automatically update proxy software and drivers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			updateCfg := config.DefaultUpdate()
			cfgFile := ""
			if configPath != nil && *configPath != "" {
				if info, err := os.Stat(*configPath); err == nil && info.Mode().IsRegular() {
					cfg, err := config.Load(*configPath)
					if err != nil {
						return fmt.Errorf("load config %s: %w", *configPath, err)
					}
					updateCfg = cfg.Update
					cfgFile = *configPath
				}
			}
			if repo != "" {
				updateCfg.Repo = repo
			}
			if baseURL != "" {
				updateCfg.BaseURL = baseURL
			}

			var progress io.Writer
			if !asJSON {
				progress = cmd.OutOrStdout()
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()

			opts := updater.Options{
				Repo:          updateCfg.Repo,
				BaseURL:       updateCfg.BaseURL,
				Channel:       updateCfg.Channel,
				TargetVersion: version,
				Prerelease:    prerelease,
				Force:         force,
				ConfigPath:    cfgFile,
				Progress:      progress,
			}

			client := updater.NewClient(nil)
			check, err := client.Check(ctx, opts)
			if err != nil {
				return err
			}

			if checkOnly || !check.UpdateAvailable {
				if asJSON {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(check)
				}
				if !check.UpdateAvailable {
					fmt.Fprintf(cmd.OutOrStdout(), "Proxy is already up to date (%s).\n", check.CurrentVersion)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Update available: %s -> %s (%s)\n", check.CurrentVersion, check.TargetVersion, check.Reason)
				if check.DriverUpdateNeeded {
					fmt.Fprintln(cmd.OutOrStdout(), "Windows WinDivert driver update will be included.")
				}
				return nil
			}

			if progress != nil {
				fmt.Fprintf(progress, "Updating Proxy %s -> %s (%s)...\n", check.CurrentVersion, check.TargetVersion, check.Reason)
			}

			exePath, _ := os.Executable()
			preferDeb := updater.PreferDeb(exePath)
			staged, err := client.Stage(ctx, opts, check, preferDeb)
			if err != nil {
				return err
			}
			defer staged.Cleanup()

			res, err := updater.Apply(ctx, staged, updater.ApplyOptions{
				ExecutablePath: exePath,
				ConfigPath:     cfgFile,
				Progress:       progress,
			})
			if err != nil {
				return err
			}

			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Updated Proxy to %s (method=%s).\n", res.UpdatedVersion, res.Method)
			if res.DriverNote != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Driver: %s.\n", res.DriverNote)
			}
			if len(res.GeoSynced) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Geo data synced: %v.\n", res.GeoSynced)
			}
			if res.ServiceRestarted {
				fmt.Fprintln(cmd.OutOrStdout(), "Background service restarted and running.")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "check for updates without installing")
	cmd.Flags().StringVar(&version, "version", "", "install a specific release tag (e.g. v0.2.0)")
	cmd.Flags().BoolVar(&force, "force", false, "force reinstall software and driver even if already up to date")
	cmd.Flags().BoolVar(&prerelease, "prerelease", false, "allow updating to prerelease versions")
	cmd.Flags().StringVar(&repo, "repo", "", "override GitHub repository (owner/repo)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "override release download base URL (mirror)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit result as JSON")
	return cmd
}
