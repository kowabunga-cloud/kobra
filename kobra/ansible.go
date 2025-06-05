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
	"os"
	"path/filepath"
	"strings"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	AnsibleBin         = "ansible"
	AnsiblePlaybookBin = "ansible-playbook"
	AnsibleGalaxyBin   = "ansible-galaxy"
	AnsibleConfigFile  = "ansible.cfg"

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

		args = append(args, "--user")
		args = append(args, user)
		args = append(args, "--key-file")
		args = append(args, keyFile)

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

func RunAnsible(cfg *KobraConfig, playbook string, upgrade, check, bootstrap, listTags bool, tags, skip_tags, extraVars, limit string, verbose, bypass bool, freeArgs []string) error {
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
	err = SetupPlatformToolchain(ptfCfg, ToolchainToolAnsible)
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

func RunAnsiblePull(cfg *KobraConfig) error {
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
	err = SetupPlatformToolchain(ptfCfg, ToolchainToolAnsible)
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
