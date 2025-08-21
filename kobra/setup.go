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
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unicode"

	"github.com/codeclysm/extract/v4"
	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
	"github.com/oriser/regroup"
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

	ToolchainToolTF       = "tf"
	ToolchainToolHelm     = "helm"
	ToolchainToolHelmfile = "helmfile"
	ToolchainToolAnsible  = "ansible"

	PythonBin = "python3"
	PipBin    = "pip3"
)

type GitHubRelease struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	PreRelease bool   `json:"prerelease"`
}

type PypiSimpleManifest struct {
	Releases []string `json:"versions"`
}

type ThirdPartyTool struct {
	Name       string
	Version    string
	GitHubRepo string
	SourceURI  string
	Binaries   []string
	BinaryName string
	PypiRepo   string
	PipAddOns  map[string]string
}

var toolchainTools = map[string]ThirdPartyTool{
	TerraformBin: ThirdPartyTool{
		Name:       "Terraform",
		GitHubRepo: "hashicorp/terraform",
		SourceURI:  "https://releases.hashicorp.com/terraform/{VERSION}/terraform_{VERSION}_{OS}_{ARCH}.zip",
		Binaries:   []string{TerraformBin},
	},
	OpenTofuBin: ThirdPartyTool{
		Name:       "OpenTofu",
		GitHubRepo: "opentofu/opentofu",
		SourceURI:  "https://github.com/opentofu/opentofu/releases/download/v{VERSION}/tofu_{VERSION}_{OS}_{ARCH}.zip",
		Binaries:   []string{OpenTofuBin},
	},
	HelmBin: ThirdPartyTool{
		Name:       "Helm",
		GitHubRepo: "helm/helm",
		SourceURI:  "https://get.helm.sh/helm-v{VERSION}-{OS}-{ARCH}.tar.gz",
		Binaries:   []string{fmt.Sprintf("%s-%s/%s", runtime.GOOS, runtime.GOARCH, HelmBin)},
	},
	HelmfileBin: ThirdPartyTool{
		Name:       "Helmfile",
		GitHubRepo: "helmfile/helmfile",
		SourceURI:  "https://github.com/helmfile/helmfile/releases/download/v{VERSION}/helmfile_{VERSION}_{OS}_{ARCH}.tar.gz",
		Binaries:   []string{HelmfileBin},
	},
	AnsibleBin: ThirdPartyTool{
		Name:     "Ansible",
		PypiRepo: "ansible",
		PipAddOns: map[string]string{
			"jmespath":   ToolchainVersionLatest,
			"boto3":      ToolchainVersionLatest,
			"botocore":   ToolchainVersionLatest,
			"kubernetes": ToolchainVersionLatest,
			"netaddr":    ToolchainVersionLatest,
			"jsonpatch":  ToolchainVersionLatest,
			"PyYAML":     ToolchainVersionLatest,
			"pypsrp":     ToolchainVersionLatest,
		},
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

func (tp *ThirdPartyTool) PipInstall(venvDir string) error {
	klog.Infof("Installing Python's %s %s ...", tp.Name, tp.Version)
	err := pipInstallPkg(venvDir, tp.PypiRepo, tp.Version)
	if err != nil {
		return err
	}

	return nil
}

func (tp *ThirdPartyTool) PipCheckAndInstall(venvDir, requestedVersion string, update bool) error {
	pkgVersion, err := findPythonPkgVersion(venvDir, tp.PypiRepo)
	if err != nil {
		return err
	}

	if pkgVersion != requestedVersion {
		errVersion := findPlatformPythonPkgVersion(tp, pkgVersion, requestedVersion)
		if errVersion != nil {
			return errVersion
		}

		if pkgVersion != tp.Version {
			errExtract := tp.PipInstall(venvDir)
			if errExtract != nil {
				return errExtract
			}
		}
	}

	return nil
}

func findPythonPkgVersion(venvDir, pkg string) (string, error) {
	var version string
	err := filepath.Walk(fmt.Sprintf("%s/lib", venvDir),
		func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				return nil
			}

			base := filepath.Base(path)
			if strings.HasPrefix(base, fmt.Sprintf("%s-", pkg)) &&
				strings.HasSuffix(base, ".dist-info") {
				r := regroup.MustCompile(fmt.Sprintf(`%s-(?P<Version>.*)\.dist-info`, pkg))
				matches, errReg := r.Groups(base)
				if errReg != nil {
					return errReg
				}

				if version == "" {
					version = matches["Version"]
				}
			}
			return nil
		})
	klog.Debugf("Found Python package %s version %s in toolchain", pkg, version)
	return version, err
}

func createPythonVirtualEnv(dst string, update bool) error {
	// check for previous existence
	_, err := LookupPlatformBinary(PipBin)
	if err != nil || update {
		// it doesn't, let's create it
		python, err := LookupSystemBinary(PythonBin)
		if err != nil {
			return err
		}

		args := []string{
			"-m",
			"venv",
			dst,
		}

		klog.Infof("Creating Python3 virtual environment ...")
		return BinExec(python, "", args, []string{})
	}

	return nil
}

func pipInstallPkg(dst, pkg, version string) error {
	pip, err := LookupPlatformBinary(PipBin)
	if err != nil {
		return err
	}

	pkgVersion := pkg
	if version != "" {
		pkgVersion = fmt.Sprintf("%s==%s", pkg, version)
	}
	args := []string{
		"install",
		pkgVersion,
	}

	out, err := BinExecOut(pip, "", args, []string{})
	if err != nil {
		return err
	}

	klog.Debug(out)
	return nil
}

func hasLetter(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsLetter(r)
	})
}

func findPlatformPythonPkgVersion(tp *ThirdPartyTool, currentVersion, requestedVersion string) error {
	pkgUri := fmt.Sprintf("https://pypi.org/simple/%s/", tp.PypiRepo)

	client := &http.Client{}
	req, errGet := http.NewRequest("GET", pkgUri, nil)
	if errGet != nil {
		return KobraError("%s", errGet.Error())
	}

	req.Header.Add("Accept", "application/vnd.pypi.simple.v1+json")
	resp, errGet := client.Do(req)
	if errGet != nil {
		return KobraError("%s", errGet.Error())
	}

	body, errGet := io.ReadAll(resp.Body)
	if errGet != nil {
		return KobraError("%s", errGet.Error())
	}

	var manifest PypiSimpleManifest
	_ = json.Unmarshal(body, &manifest)

	if requestedVersion != ToolchainVersionLatest {
		// explicit version request
		found := false
		for _, r := range manifest.Releases {
			if r == requestedVersion {
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
		releaseVersions := []string{}
		for _, r := range manifest.Releases {
			blacklistedKeywords := []string{"dev", "rc"}
			for _, k := range blacklistedKeywords {
				if strings.Contains(r, k) {
					continue
				}
			}

			if hasLetter(r) {
				continue
			}

			releaseVersions = append(releaseVersions, r)
		}
		if len(releaseVersions) == 0 {
			return fmt.Errorf("unable to find latest stable release for %s", tp.Name)
		}

		tp.Version = releaseVersions[len(releaseVersions)-1]
	}

	return nil
}

func findPlatformBinaryVersion(tp *ThirdPartyTool, currentVersion, requestedVersion string) error {
	releaseUri := fmt.Sprintf("https://api.github.com/repos/%s/releases", tp.GitHubRepo)
	resp, errGet := http.Get(releaseUri) // #nosec G107
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

func SetupPlatformToolchain(cfg *PlatformConfig, update bool, tools ...string) error {
	if cfg.Toolchain.UseSystem {
		return nil
	}

	binDir, err := LookupPlatformBinDir()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	for _, tool := range tools {
		currentVersion := "undefined"
		switch tool {
		case ToolchainToolTF:
			binName := OpenTofuBin
			if cfg.Toolchain.TF.Provider == TfProviderTerraform {
				binName = TerraformBin
			}
			tp := toolchainTools[binName]

			binExe, err := LookupPlatformBinary(binName)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
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

			requestedVersion := cfg.Toolchain.TF.Version
			if err != nil || (update && currentVersion != requestedVersion) {
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
		case ToolchainToolHelm:
			tp := toolchainTools[HelmBin]

			binExe, err := LookupPlatformBinary(HelmBin)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}

			out, err := BinExecOutNoErr(binExe, binDir, []string{"version", "--template", "{{.Version}}"}, []string{})
			if err == nil {
				currentVersion = strings.TrimSuffix(out, "\n")
				currentVersion = strings.ReplaceAll(currentVersion, "v", "")
			}

			requestedVersion := cfg.Toolchain.Helm.Version
			if err != nil || (update && currentVersion != requestedVersion) {
				errVersion := findPlatformBinaryVersion(&tp, currentVersion, requestedVersion)
				if errVersion != nil {
					return errVersion
				}

				if currentVersion != tp.Version {
					errExtract := tp.ExtractFromTarballArchive(binDir)
					if errExtract != nil {
						return errExtract
					}
				}
			}
		case ToolchainToolHelmfile:
			tp := toolchainTools[HelmfileBin]

			binExe, err := LookupPlatformBinary(HelmfileBin)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}

			out, err := BinExecOut(binExe, binDir, []string{"version", "-o", "short"}, []string{})
			if err == nil {
				currentVersion = strings.TrimSuffix(out, "\n")
			}

			requestedVersion := cfg.Toolchain.Helmfile.Version
			if err != nil || (update && currentVersion != requestedVersion) {
				errVersion := findPlatformBinaryVersion(&tp, currentVersion, requestedVersion)
				if errVersion != nil {
					return errVersion
				}

				if currentVersion != tp.Version {
					errExtract := tp.ExtractFromTarballArchive(binDir)
					if errExtract != nil {
						return errExtract
					}
				}
			}
		case ToolchainToolAnsible:
			venvDir, err := LookupPlatformConfigDir()
			if err != nil {
				return err
			}

			err = createPythonVirtualEnv(venvDir, update)
			if err != nil {
				return err
			}

			tp := toolchainTools[AnsibleBin]
			err = tp.PipCheckAndInstall(venvDir, cfg.Toolchain.Ansible.Version, update)
			if err != nil {
				return err
			}

			// install extra packages
			addOns := map[string]string{}
			maps.Insert(addOns, maps.All(tp.PipAddOns))
			maps.Insert(addOns, maps.All(cfg.Toolchain.Ansible.Packages)) // local overrides, if any

			for pkg, version := range addOns {
				pipTp := ThirdPartyTool{
					Name:     pkg,
					PypiRepo: pkg,
				}

				err := pipTp.PipCheckAndInstall(venvDir, version, update)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
