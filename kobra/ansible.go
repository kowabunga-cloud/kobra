/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kowabunga-cloud/common/klog"
)

const (
	AnsibleBin                  = "ansible"
	AnsiblePlaybookBin          = "ansible-playbook"
	AnsiblePlaybookInventoryBin = "ansible-inventory"
	AnsibleGalaxyBin            = "ansible-galaxy"
	AnsibleConfigFile           = "ansible.cfg"

	AnsibleIniSection             = "defaults"
	AnsibleIniCollections         = "collections_paths"
	AnsibleIniRoles               = "roles_path"
	AnsibleIniInventory           = "inventory"
	AnsiblePlaybooksDir           = "playbooks"
	AnsibleRolesPathDefault       = "./roles"
	AnsibleCollectionsPathDefault = "./collections"
	AnsibleCollectionsSpecialPath = "ansible_collections"
	AnsibleRequirements           = "requirements.yml"
	AnsibleInventoryFile          = "hosts.txt"
	AnsibleInventoryDir           = "inventories"
	AnsibleHostsLocal             = "localhost"
	AnsibleConnectionLocal        = "local"
)

type PlaybookTarget struct {
	Hosts      string `yaml:"hosts"`
	Connection string `yaml:"connection,omitempty"`
}

func ansibleChecks(ansibleDir string) error {
	cfgFile := fmt.Sprintf("%s/%s", ansibleDir, AnsibleConfigFile)
	_, err := os.Stat(cfgFile)
	if err != nil {
		return KobraError("Can't find %s", cfgFile)
	}

	return nil
}

func readAnsibleConfig(ansibleDir string) (string, string, string, error) {
	cfgFile := fmt.Sprintf("%s/%s", ansibleDir, AnsibleConfigFile)
	cfg, err := ini.Load(cfgFile)
	if err != nil {
		klog.Errorf("unable to parse %s", cfgFile)
		return "", "", "", err
	}

	collections := cfg.Section(AnsibleIniSection).Key(AnsibleIniCollections).String()
	if collections == "" {
		collections = AnsibleCollectionsPathDefault
	}

	roles := cfg.Section(AnsibleIniSection).Key(AnsibleIniRoles).String()
	if roles == "" {
		roles = AnsibleRolesPathDefault
	}

	inventory := cfg.Section(AnsibleIniSection).Key(AnsibleIniInventory).String()

	return collections, roles, inventory, nil
}

func galaxyCollect(ptfCfg *PlatformConfig, ansibleDir string) error {
	cfgFile := fmt.Sprintf("%s/%s", ansibleDir, AnsibleConfigFile)
	envs := []string{
		fmt.Sprintf("ANSIBLE_CONFIG=%s", cfgFile),
	}

	args := []string{
		"install",
		"-r",
		AnsibleRequirements,
		"-f",
	}

	klog.Infof("Pulling required Ansible role(s) and collection(s) ...")

	var galaxy string
	var err error
	if ptfCfg.Toolchain.UseSystem {
		galaxy, err = LookupSystemBinary(AnsibleGalaxyBin)
	} else {
		galaxy, err = LookupPlatformBinary(AnsibleGalaxyBin)
	}
	if err != nil {
		return err
	}

	return BinExec(galaxy, ansibleDir, args, envs)
}

func findPlaybook(ansibleDir, collectionDir, playbook string) (string, error) {
	var pbook string

	if playbook == "" {
		return "", KobraError("no playbook specified, can't go anyfurther.")
	}

	searchPaths := []string{
		ansibleDir,
		fmt.Sprintf("%s/%s", ansibleDir, AnsiblePlaybooksDir),
	}
	for _, sp := range searchPaths {
		pb := fmt.Sprintf("%s/%s", sp, playbook)
		if !strings.Contains(playbook, ".yml") {
			pb = fmt.Sprintf("%s/%s.yml", sp, playbook)
		}
		_, err := os.Stat(pb)
		if err == nil {
			pbook = pb
			break
		}
	}

	// may it come from a collection ?
	if pbook == "" {
		// should be namespace.collection.playbook
		pbCollection := strings.Split(playbook, ".")
		if len(pbCollection) == 3 {
			pb := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", ansibleDir, collectionDir, AnsibleCollectionsSpecialPath, pbCollection[0], pbCollection[1], AnsiblePlaybooksDir, pbCollection[2])
			if !strings.Contains(pb, ".yml") {
				pb += ".yml"
			}
			klog.Debugf("Looking for collection playbook for %s", pb)
			_, err := os.Stat(pb)
			if err == nil {
				klog.Infof("Found playbook in collection.")
				pbook = pb
			}
		}
	}

	if pbook == "" {
		return "", KobraError("no playbook '%s', can be found.", playbook)
	}

	return pbook, nil
}

func findInventory(ansibleDir string) string {

	searchPaths := []string{
		ansibleDir,
		fmt.Sprintf("%s/%s", ansibleDir, AnsibleInventoryDir),
	}
	for _, sp := range searchPaths {
		inv := fmt.Sprintf("%s/%s", sp, AnsibleInventoryFile)
		_, err := os.Stat(inv)
		if err == nil {
			return inv
		}
	}

	// nothing can be found, try to pick something as close as possible
	for _, sp := range searchPaths {
		re := fmt.Sprintf("%s/hosts*.txt", sp)
		matches, err := filepath.Glob(re)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return matches[0]
		}
	}

	return ""
}

func playbookTargets(playbook string) ([]PlaybookTarget, error) {

	targets := []PlaybookTarget{}

	pb, err := os.ReadFile(filepath.Clean(playbook))
	if err != nil {
		return targets, err
	}

	err = yaml.Unmarshal(pb, &targets)
	if err != nil {
		return targets, KobraError("%s", err.Error())
	}

	return targets, nil
}

func compilePatterns(patterns []string) (*regexp.Regexp, error) {
	combined := "(" + strings.Join(patterns, ")|(") + ")"
	return regexp.Compile(combined)
}

func walkAndReplace(data any, re *regexp.Regexp, newValue string) any {
	switch t := data.(type) {
	case map[string]any:
		for k, v := range t {
			// Check if the key matches the regex pattern
			if re.MatchString(k) {
				t[k] = newValue
			} else {
				// Recurse into nested structures
				t[k] = walkAndReplace(v, re, newValue)
			}
		}
	case []any:
		for i, v := range t {
			t[i] = walkAndReplace(v, re, newValue)
		}
	}
	return data
}

func runPlaybook(ptfCfg *PlatformConfig, secrets *KobraSecretData, ansibleDir, inventory, playbook, tags, skip_tags, extraVars, limit string, check, bootstrap, listTags, verbose bool, freeArgs []string) error {
	// find requested binary
	var bin string
	var err error
	if ptfCfg.Toolchain.UseSystem {
		bin, err = LookupSystemBinary(AnsiblePlaybookBin)
	} else {
		bin, err = LookupPlatformBinary(AnsiblePlaybookBin)
	}
	if err != nil {
		return err
	}

	// set environment variables
	cfgFile := fmt.Sprintf("%s/%s", ansibleDir, AnsibleConfigFile)
	envs := []string{
		fmt.Sprintf("ANSIBLE_CONFIG=%s", cfgFile),
	}

	envSops, sops, err := setSopsEnv(secrets)
	if err != nil {
		return err
	}
	if sops != "" {
		defer func() {
			_ = os.Remove(sops)
		}()
	}

	envs = append(envs, envSops...)

	if !ptfCfg.Toolchain.UseSystem {
		path := os.Getenv("PATH")
		binDir, err := LookupPlatformBinDir()
		if err != nil {
			return err
		}

		if path != "" {
			envs = append(envs, fmt.Sprintf("PATH=%s:%s", binDir, path))
		}
	}

	// set command-line arguments
	args := []string{
		"--diff",
	}

	// set static inventory file if not specified as part of local configuration
	if inventory == "" {
		inv := findInventory(ansibleDir)
		if inv != "" {
			args = append(args, "-i")
			args = append(args, inv)
		}
	}

	// add check routines ?
	if check {
		args = append(args, "--check")
	}

	// list available tags ?
	if listTags {
		args = append(args, "--list-tags")
	}

	// check for host targets
	targets, err := playbookTargets(playbook)
	if err != nil {
		return err
	}

	// check for local connection location
	localConnection := false
	for _, t := range targets {
		if t.Hosts == AnsibleHostsLocal && t.Connection == AnsibleConnectionLocal {
			localConnection = true
		}
	}

	// set SSH credentials if not local connection
	if !localConnection {
		// ssh user to use ?
		user, keyFile, err := GetSSHCredentials(ptfCfg, bootstrap)
		if err != nil {
			return err
		}

		if user != "" {
			args = append(args, "--user")
			args = append(args, user)
		}
		if keyFile != "" {
			args = append(args, "--key-file")
			args = append(args, keyFile)
		}

		// become admin
		args = append(args, "--become")
	}

	// add extra variables if required
	if extraVars != "" {
		args = append(args, "-e")
		args = append(args, extraVars)
	}

	// add tags if required
	if tags != "" {
		args = append(args, "--tags")
		args = append(args, tags)
	}

	// add skip tags if required
	if skip_tags != "" {
		args = append(args, "--skip-tags")
		args = append(args, skip_tags)
	}

	// check for extra verbosity
	if verbose {
		args = append(args, "-vv")
	}

	// check for limit
	if limit != "" {
		args = append(args, "--limit")
		args = append(args, limit)
	}

	// add free args, if any
	args = append(args, freeArgs...)

	// and finally add playbook file
	args = append(args, playbook)

	klog.Info("Running Ansible playbook ...")
	return BinExec(bin, ansibleDir, args, envs)
}

func runInventory(ptfCfg *PlatformConfig, secrets *KobraSecretData, ansibleDir, cmd, inventory, pbook, group, host, outputFile, extraVars, limit string, verbose bool, freeArgs []string) error {
	// find requested binary
	var bin string
	var err error
	if ptfCfg.Toolchain.UseSystem {
		bin, err = LookupSystemBinary(AnsiblePlaybookInventoryBin)
	} else {
		bin, err = LookupPlatformBinary(AnsiblePlaybookInventoryBin)
	}
	if err != nil {
		return err
	}

	// set environment variables
	cfgFile := fmt.Sprintf("%s/%s", ansibleDir, AnsibleConfigFile)
	envs := []string{
		fmt.Sprintf("ANSIBLE_CONFIG=%s", cfgFile),
	}

	envSops, sops, err := setSopsEnv(secrets)
	if err != nil {
		return err
	}
	if sops != "" {
		defer func() {
			_ = os.Remove(sops)
		}()
	}

	envs = append(envs, envSops...)

	if !ptfCfg.Toolchain.UseSystem {
		path := os.Getenv("PATH")
		binDir, err := LookupPlatformBinDir()
		if err != nil {
			return err
		}

		if path != "" {
			envs = append(envs, fmt.Sprintf("PATH=%s:%s", binDir, path))
		}
	}

	// set command-line arguments
	args := []string{
		fmt.Sprintf("--%s", cmd),
	}

	// set group or host, if requested
	if cmd == cmdAnsibleInventoryActionGraph && group != "" {
		args = append(args, group)
	}

	if cmd == cmdAnsibleInventoryActionHost && host != "" {
		args = append(args, host)
	}

	// set static inventory file if not specified as part of local configuration
	if inventory == "" {
		inv := findInventory(ansibleDir)
		if inv != "" {
			args = append(args, "-i")
			args = append(args, inv)
		}
	}

	if pbook != "" {
		args = append(args, "--playbook-dir")
		args = append(args, filepath.Dir(pbook))
	}

	if cmd == cmdAnsibleInventoryActionGraph {
		args = append(args, "--vars")
		if limit != "" {
			args = append(args, "--limit")
			args = append(args, limit)
		}
	}

	if cmd == cmdAnsibleInventoryActionHost {
		args = append(args, "--yaml")
	}

	if cmd == cmdAnsibleInventoryActionList {
		args = append(args, "--yaml")
		if outputFile != "" {
			args = append(args, "--output")
			args = append(args, outputFile)
		}
	}

	// check for extra args
	if extraVars != "" {
		args = append(args, "--extra-vars")
		args = append(args, extraVars)
	}

	// check for verbose output
	if verbose {
		args = append(args, "--verbose")
	}

	// add free args, if any
	args = append(args, freeArgs...)

	klog.Info("Running Ansible inventory ...")
	return BinExec(bin, ansibleDir, args, envs)
}

func runExport(ptfCfg *PlatformConfig, secrets *KobraSecretData, ansibleDir, inventory, pbook, out, extraVars string, filters []string, verbose bool, freeArgs []string) error {
	tmpFile, err := os.CreateTemp("", "kobra-ansible-inventory-*.yml")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()
	defer func() {
		_ = tmpFile.Close()
	}()

	err = runInventory(ptfCfg, secrets, ansibleDir, cmdAnsibleInventoryActionList, inventory, pbook, "", "", tmpFile.Name(), extraVars, "", verbose, freeArgs)
	if err != nil {
		return err
	}

	f, err := os.Open(filepath.Clean(tmpFile.Name())) // #nosec G304
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	contents, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	// unmarshal into a generic interface
	var obj any
	err = yaml.Unmarshal(contents, &obj)
	if err != nil {
		return err
	}

	// perform the recursive replacement
	re, err := compilePatterns(filters)
	if err != nil {
		return err
	}

	updatedObj := walkAndReplace(obj, re, "REDACTED")

	// now parse inventory results into a generic map for further processing
	iv := updatedObj.(map[string]interface{})

	all, ok := iv["all"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("YAML inventory structure is missing 'all' node")
	}

	children, ok := all["children"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("YAML inventory structure is missing 'children' node")
	}

	// iterate through dynamic groups
	for groupName, groupData := range children {
		klog.Debugf("Processing inventory group: %s", groupName)

		groupMap, ok := groupData.(map[string]interface{})
		if !ok {
			continue
		}

		hosts, ok := groupMap["hosts"].(map[string]interface{})
		if !ok {
			continue
		}

		//		if filepath.IsAbs(out) {

		outDir := fmt.Sprintf("%s/%s", out, groupName)
		err := os.MkdirAll(outDir, 0755) // #nosec G301
		if err != nil {
			return err
		}

		// iterate through dynamic hosts
		for hostName, hostVars := range hosts {
			klog.Debugf("Extracting variables from %s", hostName)

			// marshal only this host's variables
			hostYaml, err := yaml.Marshal(hostVars)
			if err != nil {
				klog.Errorf("Error marshaling host %s: %v", hostName, err)
				continue
			}

			// output to one YAML file per host
			fileName := fmt.Sprintf("%s/%s.yml", outDir, hostName)
			err = os.WriteFile(fileName, hostYaml, 0644) // #nosec G306
			if err != nil {
				klog.Errorf("Error writing file %s: %v", fileName, err)
				continue
			}
		}
	}
	klog.Infof("Exported inventory variables to %s", out)

	return nil
}

func RunAnsible(toolchainUpdate bool, playbook string, upgrade, check, bootstrap, listTags bool, tags, skip_tags, extraVars, limit string, verbose, bypass bool, freeArgs []string) error {
	// get Ansible dir
	ansibleDir, err := LookupAnsibleDir()
	if err != nil {
		return err
	}

	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return err
	}

	// setup toolchain, if needed
	err = SetupPlatformToolchain(ptfCfg, toolchainUpdate, ToolchainToolAnsible, ToolchainToolSops)
	if err != nil {
		return err
	}

	// ensure we're in the right place
	err = ansibleChecks(ansibleDir)
	if err != nil {
		return err
	}

	// pull roles and collections, if requested
	if upgrade {
		err = galaxyCollect(ptfCfg, ansibleDir)
		if err != nil {
			return err
		}
	}

	// read out local Ansible configuration
	collectionDir, _, inventory, err := readAnsibleConfig(ansibleDir)
	if err != nil {
		return err
	}

	// get secrets
	secrets, err := GetSecrets(ptfCfg)
	if err != nil {
		return err
	}

	// ensure we got a valid playbook to run
	pbook, err := findPlaybook(ansibleDir, collectionDir, playbook)
	if err != nil {
		return err
	}

	// don't deploy from outdated branch
	ready, err := IsGitRepoUpToDate(ptfCfg, bypass)
	if !ready || err != nil {
		return err
	}

	// finally try to run the playbook
	return runPlaybook(ptfCfg, secrets, ansibleDir, inventory, pbook, tags, skip_tags, extraVars, limit, check, bootstrap, listTags, verbose, freeArgs)
}

func RunAnsiblePull() error {
	// get Ansible dir
	ansibleDir, err := LookupAnsibleDir()
	if err != nil {
		return err
	}

	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return err
	}

	// setup toolchain, if needed
	err = SetupPlatformToolchain(ptfCfg, false, ToolchainToolAnsible)
	if err != nil {
		return err
	}

	// ensure we're in the right place
	err = ansibleChecks(ansibleDir)
	if err != nil {
		return err
	}

	// pull roles and collections
	err = galaxyCollect(ptfCfg, ansibleDir)
	if err != nil {
		return err
	}

	return nil
}

func RunAnsibleInventory(toolchainUpdate bool, cmd, playbook, group, host, out, extraVars, limit string, filters []string, verbose bool, freeArgs []string) error {
	// get Ansible dir
	ansibleDir, err := LookupAnsibleDir()
	if err != nil {
		return err
	}

	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return err
	}

	// setup toolchain, if needed
	err = SetupPlatformToolchain(ptfCfg, toolchainUpdate, ToolchainToolAnsible, ToolchainToolSops)
	if err != nil {
		return err
	}

	// ensure we're in the right place
	err = ansibleChecks(ansibleDir)
	if err != nil {
		return err
	}

	// read out local Ansible configuration
	collectionDir, _, inventory, err := readAnsibleConfig(ansibleDir)
	if err != nil {
		return err
	}

	// get secrets
	secrets, err := GetSecrets(ptfCfg)
	if err != nil {
		return err
	}

	// optional: check if a valid playbook argument has been passed
	var pbook string
	if playbook != "" {
		pbook, _ = findPlaybook(ansibleDir, collectionDir, playbook)
	}

	if cmd == cmdAnsibleInventoryActionExport {
		if !filepath.IsAbs(out) {
			ptfDir, err := LookupPlatformDir()
			if err != nil {
				return err
			}
			out = fmt.Sprintf("%s/%s", ptfDir, out)
		}
		return runExport(ptfCfg, secrets, ansibleDir, inventory, pbook, out, extraVars, filters, verbose, freeArgs)
	}

	// fallback to all other actions, finally try to run the inventory
	return runInventory(ptfCfg, secrets, ansibleDir, cmd, inventory, pbook, group, host, out, extraVars, limit, verbose, freeArgs)
}
