/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"archive/zip"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/codeclysm/extract/v4"
	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	KobraConfigPluginsManifestFile = "MANIFEST.json"

	KobraThirdPartyTemplateUriVersion    = "{VERSION}"
	KobraThirdPartyTemplateUriArch       = "{ARCH}"
	KobraThirdPartyTemplateUriArchAlt    = "{ARCH_ALT}"
	KobraThirdPartyTemplateUriArchAlt2   = "{ARCH_ALT2}"
	KobraThirdPartyTemplateUriArchCompat = "{ARCH_COMPAT}"
	KobraThirdPartyTemplateUriOs         = "{OS}"
	KobraThirdPartyTemplateUriOsAlt      = "{OS_ALT}"
	KobraThirdPartyTemplateUriOsAlt2     = "{OS_ALT2}"
)

type GitHubRelease struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	PreRelease bool   `json:"prerelease"`
}

type ThirdPartyTool struct {
	Name       string
	Version    string
	GitHubRepo string
	SourceURI  string
	Binaries   []string
	BinaryName string
	IsTarball  bool
	IsZipped   bool
}

var thirdPartyTools = []ThirdPartyTool{
	ThirdPartyTool{
		Name:      "SOPS",
		Version:   "3.10.2",
		SourceURI: "https://github.com/getsops/sops/releases/download/v{VERSION}/sops-v{VERSION}.{OS}.{ARCH}",
		Binaries:  []string{SopsBin},
	},
	ThirdPartyTool{
		Name:      "Age",
		Version:   "1.2.1",
		SourceURI: "https://github.com/FiloSottile/age/releases/download/v{VERSION}/age-v{VERSION}-{OS}-{ARCH}.tar.gz",
		Binaries:  []string{fmt.Sprintf("age/%s", AgeBin), fmt.Sprintf("age/%s", AgeKeygenBin)},
		IsTarball: true,
	},
}

var toolchainTools = map[string]ThirdPartyTool{
	TerraformBin: ThirdPartyTool{
		Name:       "Terraform",
		Version:    "1.12.0",
		GitHubRepo: "hashicorp/terraform",
		SourceURI:  "https://releases.hashicorp.com/terraform/{VERSION}/terraform_{VERSION}_{OS}_{ARCH}.zip",
		Binaries:   []string{TerraformBin},
		IsZipped:   true,
	},
	OpenTofuBin: ThirdPartyTool{
		Name:       "OpenTofu",
		Version:    "1.9.1",
		GitHubRepo: "opentofu/opentofu",
		SourceURI:  "https://github.com/opentofu/opentofu/releases/download/v{VERSION}/tofu_{VERSION}_{OS}_{ARCH}.zip",
		Binaries:   []string{OpenTofuBin},
		IsZipped:   true,
	},
}

type ProgressReader struct {
	Name   string
	Reader io.Reader
	Size   int64
	Pos    int64
}

func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.Reader.Read(p)
	if err == nil {
		pr.Pos += int64(n)
		fmt.Printf("\rDownloading %s ... %.2f%%", pr.Name, float64(pr.Pos)/float64(pr.Size)*100)
	}
	return n, err
}

func TemplatedURI(uri, version string) string {

	mappingsAlt := map[string]string{
		// architectures
		"amd64": "x86_64",
		"arm64": "arm64",
		// operating systems
		"linux":  "Linux",
		"darwin": "macOS",
	}
	archAlt := mappingsAlt[runtime.GOARCH]
	osAlt := mappingsAlt[runtime.GOOS]

	mappingsAlt2 := map[string]string{
		// architectures
		"amd64": "x86_64",
		"arm64": "aarch64",
		// operating systems
		"linux":  "unknown-linux-gnu",
		"darwin": "apple-darwin",
	}
	archAlt2 := mappingsAlt2[runtime.GOARCH]
	osAlt2 := mappingsAlt2[runtime.GOOS]

	// uses emulated x86_64 on arm64
	mappingsCompat := map[string]string{
		// architectures
		"amd64": "x86_64",
		"arm64": "x86_64",
	}
	archCompat := mappingsCompat[runtime.GOARCH]

	uri = strings.ReplaceAll(uri, KobraThirdPartyTemplateUriVersion, version)
	uri = strings.ReplaceAll(uri, KobraThirdPartyTemplateUriArch, runtime.GOARCH)
	uri = strings.ReplaceAll(uri, KobraThirdPartyTemplateUriArchAlt, archAlt)
	uri = strings.ReplaceAll(uri, KobraThirdPartyTemplateUriArchAlt2, archAlt2)
	uri = strings.ReplaceAll(uri, KobraThirdPartyTemplateUriArchCompat, archCompat)
	uri = strings.ReplaceAll(uri, KobraThirdPartyTemplateUriOs, runtime.GOOS)
	uri = strings.ReplaceAll(uri, KobraThirdPartyTemplateUriOsAlt, osAlt)
	uri = strings.ReplaceAll(uri, KobraThirdPartyTemplateUriOsAlt2, osAlt2)

	return uri
}

func DownloadFile(name, src string, dst *os.File) error {
	req, err := http.NewRequest("GET", src, nil)
	if err != nil {
		klog.Errorf("unable to download %s from %s: %s", name, src, err)
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("error while downloading %s from %s: %v", name, src, resp.StatusCode)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	progressReader := &ProgressReader{
		Name:   name,
		Reader: resp.Body,
		Size:   resp.ContentLength,
	}

	_, err = io.Copy(dst, progressReader)
	if err != nil {
		klog.Errorf("Unable to download %s from %s: %s", name, src, err)
		return err
	}

	fmt.Println(" - Download completed!")

	return nil
}

func GrantExecRights(bin string) error {
	// ensure executable rights
	return os.Chmod(bin, 0750)
}

func copy(src, dst string) (int64, error) {

	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, fmt.Errorf("failed to get file info for source %s : %w", src, err)
	}
	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}
	source, err := os.Open(filepath.Clean(src))
	if err != nil {
		return 0, fmt.Errorf("failed to open file %s : %w", src, err)
	}

	defer func() {
		if sourceClose := source.Close(); sourceClose != nil {
			err = fmt.Errorf("failed to close source file %s : %w", src, err)
		}
	}()

	destination, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return 0, fmt.Errorf("failed to create destination file : %w", err)
	}

	defer func() {
		if desClose := destination.Close(); desClose != nil {
			err = fmt.Errorf("failed to close destination file %s : %w", dst, err)
		}
	}()

	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func CheckSameDevice(src string) (bool, error) {

	var idDest, idSrc uint64
	dst, err := GetConfigDir()
	if err != nil {
		return false, fmt.Errorf("failed to get Kobra config dir'%s' : %w", dst, err)
	}

	fileInfoSRC, err := os.Stat(src)
	if err != nil {
		return false, fmt.Errorf("failed to get information about this file '%s' : %w", src, err)
	}
	fileInfoDST, err := os.Stat(dst)
	if err != nil {
		return false, fmt.Errorf("failed to get information about this file '%s' : %w", dst, err)
	}
	s := fileInfoSRC.Sys()
	switch s := s.(type) {
	default:
		return false, fmt.Errorf("cannot get source file's device '%s' information : %w", src, err)
	case *syscall.Stat_t:
		idSrc = uint64(s.Dev)
	}
	d := fileInfoDST.Sys()
	switch d := d.(type) {
	default:
		return false, fmt.Errorf("cannot get destination file's device '%s' information : %w", src, err)
	case *syscall.Stat_t:
		idDest = uint64(d.Dev)
	}
	if idSrc == idDest {
		return true, nil
	} else {
		return false, nil
	}
}

func StandaloneBinary(src, dst string) error {

	sameDevice, err := CheckSameDevice(src)
	if err != nil {
		return fmt.Errorf("cannot compare binary source '%s' and destination '%s' : '%w'", src, dst, err)
	}
	if sameDevice {
		err := os.Rename(src, dst)
		if err != nil {
			return fmt.Errorf("cannot rename file source '%s' in '%s' : '%w'", src, dst, err)
		}
	} else {
		klog.Debugf("Copy file from %s to %s", src, dst)
		nbBytes, err := copy(src, dst)
		if err != nil {
			return err
		}
		klog.Debugf("Copied %d bytes", nbBytes)
	}
	if err := GrantExecRights(dst); err != nil {
		return fmt.Errorf("cannot grant execution rights to %s : %w", dst, err)
	}
	return nil
}

func (tp *ThirdPartyTool) StandaloneBinary(dst string) error {
	binFile, err := tp.Download()
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(binFile)
	}()

	return StandaloneBinary(binFile, dst)
}

func (tp *ThirdPartyTool) ExtractFromTarballArchive(dstDir string) error {

	tarFile, err := tp.Download()
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(tarFile)
	}()

	f, err := os.Open(filepath.Clean(tarFile))
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	klog.Debugf("Extracting tarball into %s", tmpDir)

	// extract compressed tarball
	err = extract.Archive(context.TODO(), f, tmpDir, nil)
	if err != nil {
		return err
	}

	// loop over requested binaries
	for _, bin := range tp.Binaries {
		src := fmt.Sprintf("%s/%s", tmpDir, bin)
		dst := fmt.Sprintf("%s/%s", dstDir, filepath.Base(bin))
		// special case if there's only one binary in archive but with incorrect name
		if tp.BinaryName != "" && len(tp.Binaries) == 1 {
			dst = fmt.Sprintf("%s/%s", dstDir, tp.BinaryName)
		}
		err := StandaloneBinary(src, dst)
		if err != nil {
			return err
		}
	}

	return nil
}

func (tp *ThirdPartyTool) ExtractFromZipArchive(dstDir string) error {

	zipFile, err := tp.Download()
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(zipFile)
	}()

	klog.Debugf("Extracting %s ...", zipFile)
	archive, err := zip.OpenReader(zipFile)
	if err != nil {
		return KobraError("%s", err.Error())
	}
	defer func() {
		_ = archive.Close()
	}()

	// loop over requested binaries
	for _, bin := range tp.Binaries {
		for _, f := range archive.File {
			dst := fmt.Sprintf("%s/%s", dstDir, bin)
			// special case if there's only one binary in archive but with incorrect name
			if tp.BinaryName != "" && len(tp.Binaries) == 1 {
				dst = fmt.Sprintf("%s/%s", dstDir, tp.BinaryName)
			}

			// skip archive content we don't care about ...
			if f.Name != bin {
				continue
			}

			// extract archive content
			klog.Debugf("Extracting %s into %s ...", f.Name, dst)

			dstFile, err := os.OpenFile(filepath.Clean(dst), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return KobraError("%s", err.Error())
			}

			fileInArchive, err := f.Open()
			if err != nil {
				return KobraError("%s", err.Error())
			}

			for {
				_, err = io.CopyN(dstFile, fileInArchive, 4096)
				if err != nil {
					if err == io.EOF {
						break
					}
					return KobraError("%s", err.Error())
				}
			}

			_ = dstFile.Close()
			_ = fileInArchive.Close()
		}
	}

	return nil
}

func (tp *ThirdPartyTool) Download() (string, error) {
	// create temporary output file
	tmpDst, err := os.CreateTemp("", "")
	if err != nil {
		return "", err
	}

	// download file to temporary dest
	name := fmt.Sprintf("%s v%s", tp.Name, tp.Version)
	src := TemplatedURI(tp.SourceURI, tp.Version)
	err = DownloadFile(name, src, tmpDst)
	if err != nil {
		return tmpDst.Name(), err
	}

	return tmpDst.Name(), nil
}

func LoadPluginsManifest() map[string]string {

	plugins := make(map[string]string)

	manifest, err := LookupConfigPluginsManifest()
	if err != nil {
		return plugins
	}

	jsonByte, err := os.ReadFile(filepath.Clean(manifest))
	if err != nil {
		return plugins
	}

	err = json.Unmarshal(jsonByte, &plugins)
	if err != nil {
		return plugins
	}

	return plugins
}

func SavePluginsManifest(plugins map[string]string) error {

	manifest, err := LookupConfigPluginsManifest()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	jsonByte, err := json.Marshal(plugins)
	if err != nil {
		return err
	}

	err = os.WriteFile(manifest, jsonByte, 0600)
	if err != nil {
		return err
	}

	return nil
}

func RunSetup(cfg *KobraConfig, force, clean bool) error {

	if clean {
		klog.Infof("Cleaning up deployment environment ...")

		pluginsDir, err := LookupConfigPluginsDir()
		if err != nil {
			return err
		}

		err = os.RemoveAll(pluginsDir)
		if err != nil {
			return err
		}
	}

	klog.Infof("Setting up deployment environment ...")

	binDir, err := LookupConfigPluginsBinDir()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	plugins := LoadPluginsManifest()
	for _, tp := range thirdPartyTools {
		// compare with manifest, skip if already present
		version, ok := plugins[tp.Name]
		if ok && version == tp.Version && !force {
			klog.Debugf("Skipping %s %s download, already present ...", tp.Name, tp.Version)
			continue
		}

		if ok && version == tp.Version && !force {
			klog.Debugf("Skipping %s %s download, already present ...", tp.Name, tp.Version)
			continue
		}

		var errExtract error
		if tp.IsTarball {
			errExtract = tp.ExtractFromTarballArchive(binDir)
		} else if tp.IsZipped {
			errExtract = tp.ExtractFromZipArchive(binDir)
		} else {
			dst := fmt.Sprintf("%s/%s", binDir, tp.Binaries[0])
			errExtract = tp.StandaloneBinary(dst)
		}
		if errExtract != nil {
			klog.Errorf("Unable to extract %s", tp.Name)
			return KobraError("%s", errExtract.Error())
		}

		plugins[tp.Name] = tp.Version

		err = SavePluginsManifest(plugins)
		if err != nil {
			return err
		}
	}

	klog.Infof("Kobra configuration has been written to %s ...", cfg.File)
	cfg.Write(cfg.File)

	found := false
	path := os.Getenv("PATH")
	if path != "" {
		for _, p := range strings.Split(path, ":") {
			if p == binDir {
				found = true
				break
			}
		}
	}

	pathDisclose := "#"
	if !found {
		pathDisclose = fmt.Sprintf(`#
#  HINT: Feel free to defaults third-party tools usage by expanding your path.
#  Add the following to your shell rc file:
#     export PATH=%s:$PATH
#`, binDir)
	}

	disclose := fmt.Sprintf(`
#######################################################################################
#
#  Kobra environment setup is now complete.
%s
#######################################################################################
`, pathDisclose)
	fmt.Println(disclose)

	return nil
}

func findPlatformBinaryVersion(tp *ThirdPartyTool, currentVersion, requestedVersion string) error {
	releaseUri := fmt.Sprintf("https://api.github.com/repos/%s/releases", tp.GitHubRepo)
	resp, errGet := http.Get(releaseUri)
	if errGet != nil {
		return KobraError("%s", errGet.Error())
	}

	body, errGet := io.ReadAll(resp.Body)
	if errGet != nil {
		return KobraError("%s", errGet.Error())
	}

	var releases []GitHubRelease
	_ = json.Unmarshal(body, &releases)

	if requestedVersion != ToolchainVersionLatest {
		// explicit version request
		tag := fmt.Sprintf("v%s", requestedVersion)
		found := false
		for _, r := range releases {
			if r.Tag == tag {
				tp.Version = requestedVersion
				found = true
				continue
			}
		}
		if !found {
			return fmt.Errorf("unable to find version %s for %s", requestedVersion, tp.Name)
		}
	} else {
		// find latest stable release
		slices.SortFunc(releases, func(a, b GitHubRelease) int {
			return cmp.Compare(a.Tag, b.Tag)
		})

		releaseVersions := []string{}
		for _, r := range releases {
			if r.Draft || r.PreRelease {
				continue
			}
			releaseVersions = append(releaseVersions, strings.ReplaceAll(r.Tag, "v", ""))
		}
		if len(releaseVersions) == 0 {
			return fmt.Errorf("unable to find latest stable release for %s", tp.Name)
		}
		tp.Version = releaseVersions[len(releaseVersions)-1]
	}

	return nil
}

func SetupPlatformToolchain(cfg *PlatformConfig, tool string) error {
	useSystem := false
	switch tool {
	case "tf":
		if cfg.TF.UseSystem {
			useSystem = true
		}
	}
	if useSystem {
		return nil
	}

	binDir, err := LookupPlatformBinDir()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	currentVersion := "undefined"
	switch tool {
	case "tf":
		binName := OpenTofuBin
		if cfg.TF.Provider == TfProviderTerraform {
			binName = TerraformBin
		}
		tp := toolchainTools[binName]

		binExe, err := LookupPlatformBinary(binName)
		if err != nil {
			return err
		}

		out, err := BinExecOut(binExe, binDir, []string{"version", "-json"}, []string{})
		if err == nil {
			type tfVersionOutput struct {
				Version string `json:"terraform_version"`
			}
			var tfv tfVersionOutput
			_ = json.Unmarshal([]byte(out), &tfv)
			currentVersion = tfv.Version
		}

		requestedVersion := cfg.TF.Version
		if err != nil || currentVersion != requestedVersion {
			errVersion := findPlatformBinaryVersion(&tp, currentVersion, requestedVersion)
			if errVersion != nil {
				return errVersion
			}

			if currentVersion != tp.Version {
				errExtract := tp.ExtractFromZipArchive(binDir)
				if errExtract != nil {
					return errExtract
				}
			}
		}
	}

	return nil
}
