// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"debug/macho"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type manifest struct {
	Version   string `json:"version"`
	Notes     string `json:"notes"`
	Date      string `json:"date"`
	URL       string `json:"url"`
	Size      int64  `json:"size"`
	Signature string `json:"signature"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "release-update:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	feed := len(args) > 0 && args[0] == "feed"
	if feed {
		args = args[1:]
	}
	flags := flag.NewFlagSet("release-update", flag.ContinueOnError)
	config := flags.String("config", "mygo.json", "MyGo configuration")
	app := flags.String("app", "build/release/MyGo Vaultwarden.app", "signed, notarized and stapled app")
	version := flags.String("version", "", "version (default CFBundleShortVersionString)")
	target := flags.String("target", "", "darwin-arm64, darwin-amd64 or darwin-universal (default Mach-O architectures)")
	out := flags.String("out", "", "output directory (default build/updates/<version>)")
	changelog := flags.String("changelog", "CHANGELOG.md", "release notes source")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	u, err := loadConfig(*config, os.LookupEnv)
	if err != nil {
		return err
	}
	if feed {
		if u == nil {
			fmt.Fprintln(os.Stderr, "Automatic updates are not configured; no update flags injected.")
			return nil
		}
		if err := validateTarget(*target); err != nil {
			return err
		}
		fmt.Printf("-X 'github.com/egoist/mygo.packageUpdateFeed=%s' -X github.com/egoist/mygo.packageUpdateKey=%s\n", u.fileURL("update-"+*target+".json", "", true), u.PublicKey)
		return nil
	}
	if u == nil {
		return fmt.Errorf("automatic updates are not configured")
	}
	absolute, err := filepath.Abs(*app)
	if err != nil {
		return err
	}
	*app = filepath.Clean(absolute)
	if *version == "" {
		*version, err = plistValue(*app, "CFBundleShortVersionString")
		if err != nil {
			return err
		}
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*$`).MatchString(*version) {
		return fmt.Errorf("version must be a nonempty filename-safe version")
	}
	if *target == "" {
		executable, err := plistValue(*app, "CFBundleExecutable")
		if err != nil {
			return err
		}
		if executable == "" || filepath.Base(executable) != executable {
			return fmt.Errorf("invalid CFBundleExecutable")
		}
		*target, err = detectTarget(filepath.Join(*app, "Contents", "MacOS", executable))
		if err != nil {
			return err
		}
	}
	if err := validateTarget(*target); err != nil {
		return err
	}
	key, err := u.signingKey(*config)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*changelog)
	if err != nil {
		return err
	}
	notes, err := releaseNotes(string(data), *version)
	if err != nil {
		return err
	}
	if *out == "" {
		*out = filepath.Join("build", "updates", *version)
	}
	files, err := generate(*app, *out, *version, *target, notes, u, key)
	if err != nil {
		return err
	}
	for _, name := range files {
		fmt.Println(name)
	}
	fmt.Println("Publish only after reviewing these files. No upload was performed.")
	if u.GitHub != "" {
		tag, repo := shellQuote(u.TagPrefix+*version), shellQuote(u.GitHub)
		fmt.Printf("GitHub examples (upload archives first, manifests last):\n  gh release create %s --repo %s --draft %s\n  gh release upload %s --repo %s %s\n", tag, repo, shellQuote(files[0]), tag, repo, shellQuote(files[1]))
		fmt.Println("Review the release notes and all targets before publishing the draft:")
		fmt.Printf("  gh release edit %s --repo %s --draft=false --latest\n", tag, repo)
		fmt.Println("For an existing release, upload the archive first, then the manifest:")
		fmt.Printf("  gh release upload %s --repo %s %s\n  gh release upload %s --repo %s %s\n", tag, repo, shellQuote(files[0]), tag, repo, shellQuote(files[1]))
	} else {
		fmt.Println("Custom server: upload the archive first, then publish the manifest at", u.fileURL("update-"+*target+".json", *version, true))
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func plistValue(app, key string) (string, error) {
	data, err := exec.Command("/usr/bin/plutil", "-extract", key, "raw", "-o", "-", filepath.Join(app, "Contents", "Info.plist")).Output()
	if err != nil {
		return "", fmt.Errorf("reading Info.plist %s: %w", key, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func validateTarget(target string) error {
	switch target {
	case "darwin-arm64", "darwin-amd64", "darwin-universal":
		return nil
	}
	return fmt.Errorf("unsupported target %q", target)
}

func detectTarget(name string) (string, error) {
	fat, err := macho.OpenFat(name)
	if err == nil {
		defer fat.Close()
		if len(fat.Arches) == 2 && ((fat.Arches[0].Cpu == macho.CpuArm64 && fat.Arches[1].Cpu == macho.CpuAmd64) || (fat.Arches[1].Cpu == macho.CpuArm64 && fat.Arches[0].Cpu == macho.CpuAmd64)) {
			return "darwin-universal", nil
		}
		return "", fmt.Errorf("unsupported fat Mach-O architectures")
	}
	if !errors.Is(err, macho.ErrNotFat) {
		return "", err
	}
	thin, err := macho.Open(name)
	if err != nil {
		return "", err
	}
	defer thin.Close()
	switch thin.Cpu {
	case macho.CpuArm64:
		return "darwin-arm64", nil
	case macho.CpuAmd64:
		return "darwin-amd64", nil
	}
	return "", fmt.Errorf("unsupported Mach-O architecture")
}

func generate(app, out, version, target, notes string, u *updates, key ed25519.PrivateKey) ([]string, error) {
	slug := strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(strings.TrimSuffix(filepath.Base(app), ".app")), "-"), "-")
	if slug == "" {
		return nil, fmt.Errorf("app name must contain letters or digits")
	}
	resolvedApp, err := filepath.EvalSymlinks(filepath.Dir(app))
	if err != nil {
		return nil, err
	}
	app = filepath.Join(resolvedApp, filepath.Base(app))
	absoluteOut, err := filepath.Abs(out)
	if err != nil {
		return nil, err
	}
	// Resolve the closest existing parent before creating anything, so even an
	// invalid output path cannot modify the signed bundle.
	existing := absoluteOut
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		existing = filepath.Dir(existing)
	}
	resolvedParent, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return nil, err
	}
	suffix, err := filepath.Rel(existing, absoluteOut)
	if err != nil {
		return nil, err
	}
	if within(app, filepath.Join(resolvedParent, suffix)) {
		return nil, fmt.Errorf("output must be outside the app bundle")
	}
	if err := os.MkdirAll(absoluteOut, 0o755); err != nil {
		return nil, err
	}
	name := slug + "-" + version + "-" + target + ".tar.gz"
	archive := filepath.Join(absoluteOut, name)
	manifestPath := filepath.Join(absoluteOut, "update-"+target+".json")
	for _, file := range []string{archive, manifestPath} {
		if _, err := os.Lstat(file); !os.IsNotExist(err) {
			return nil, fmt.Errorf("output already exists or is inaccessible: %s", file)
		}
	}
	file, err := os.CreateTemp(absoluteOut, ".archive-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	digest := sha256.New()
	err = writeArchive(io.MultiWriter(file, digest), app)
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	info, err := os.Stat(file.Name())
	if err != nil {
		return nil, err
	}
	if info.Size() > 1<<30 {
		return nil, fmt.Errorf("archive exceeds MyGo's 1 GiB download limit")
	}
	m := manifest{version, notes, time.Now().UTC().Format(time.RFC3339), u.fileURL(name, version, false), info.Size(), base64.StdEncoding.EncodeToString(ed25519.Sign(key, digest.Sum(nil)))}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(data)+1 > 1<<20 {
		return nil, fmt.Errorf("manifest exceeds MyGo's 1 MiB limit")
	}
	if err := os.Chmod(file.Name(), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(file.Name(), archive); err != nil {
		return nil, err
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o644); err != nil {
		os.Remove(archive)
		return nil, err
	}
	return []string{archive, manifestPath}, nil
}
