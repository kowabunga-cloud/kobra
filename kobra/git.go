/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/revlist"
	"github.com/go-git/go-git/v5/plumbing/transport"
	ghttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/kevinburke/ssh_config"
	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	GitOrigin = "origin"

	GitDivergenceError = "Divergence between local and remote Git branches. Stopping here ..."
	GitReadError       = "Unable to read Git repository: %s"
	GitFetchError      = "Unable to fetch remote Git repository: %s"
	GitHeadError       = "Unable to read Git local head config: %s"
	GitRemoteError     = "Unable to read from Git remote: %s"
	GitRemoteHeadError = "Unable to read Git remote head config: %s"
	GitRemoteRefError  = "Unable to find the requested remote reference"
	GitRevHistoryError = "Unable to get revisions history changes between local and remote branches"
	GitMethodError     = "Unsupported Git access method"
)

func revListCount(r *git.Repository, from, to *plumbing.Reference) (int, error) {

	commits := make([]*object.Commit, 0)

	fromHistory, err := revlist.Objects(r.Storer, []plumbing.Hash{from.Hash()}, nil)
	if err != nil {
		return 0, err
	}

	toHistory, err := revlist.Objects(r.Storer, []plumbing.Hash{to.Hash()}, fromHistory)
	if err != nil {
		return 0, err
	}

	for _, h := range toHistory {
		c, err := r.CommitObject(h)
		if err != nil {
			continue
		}
		commits = append(commits, c)
	}

	return len(commits), nil
}

func gitAuth(ptfCfg *PlatformConfig, url string) (transport.AuthMethod, error) {
	switch ptfCfg.Git.Method {
	case GitMethodSSH:
		if ptfCfg.Git.SSH.User == "" {
			ptfCfg.Git.SSH.User = GitDefaultUserSSH
		}
		if ptfCfg.Git.SSH.PrivateKey == "" {
			host := strings.Split(url, ":")[0]
			if strings.Contains(host, "@") {
				host = strings.Split(host, "@")[1]
			}
			klog.Debugf("Using Git host '%s'", host)
			ptfCfg.Git.SSH.PrivateKey = ssh_config.Get(host, "IdentityFile")

		}

		klog.Debugf("Using Git user '%s'", ptfCfg.Git.SSH.User)
		klog.Debugf("Using Git private key from %s", ptfCfg.Git.SSH.PrivateKey)

		auth, err := gssh.NewPublicKeysFromFile(ptfCfg.Git.SSH.User, ptfCfg.Git.SSH.PrivateKey, ptfCfg.Git.SSH.Password)
		if err != nil {
			return nil, err
		}
		auth.HostKeyCallback = ssh.InsecureIgnoreHostKey() // #nosec G106
		return auth, nil
	case GitMethodHTTP:
		username := ptfCfg.Git.HTTP.Username
		password := ptfCfg.Git.HTTP.Password

		if ptfCfg.Git.HTTP.Token != "" {
			// The intended use of a GitHub personal access token is in replace of your password
			// because access tokens can easily be revoked.
			// https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/
			username = "abc123" // yes, this can be anything except an empty string
			password = ptfCfg.Git.HTTP.Token
		}

		return &ghttp.BasicAuth{
			Username: username,
			Password: password,
		}, nil
	}

	return nil, fmt.Errorf("%s", GitMethodError)
}

func IsGitRepoUpToDate(ptfCfg *PlatformConfig, bypass bool) (bool, error) {

	if bypass {
		return true, nil
	}

	klog.Infof("Verifying if Git repository is up to date ...")

	ptfDir, err := LookupPlatformDir()
	if err != nil {
		return false, KobraError("%s", err.Error())
	}

	repo, err := git.PlainOpen(ptfDir)
	if err != nil {
		return false, KobraError(GitReadError, err)
	}

	// retrieves configuration
	cfg, err := repo.Config()
	if err != nil {
		return false, err
	}

	var remoteCfg *config.RemoteConfig
	for _, r := range cfg.Remotes {
		remoteCfg = r
		break
	}

	// implement proper Git access authentication
	auth, err := gitAuth(ptfCfg, remoteCfg.URLs[0])
	if err != nil {
		return false, err
	}

	// fetch from remote to ensure all objects got retrieved
	opts := git.FetchOptions{
		RemoteName: remoteCfg.Name,
		RemoteURL:  remoteCfg.URLs[0],
		Auth:       auth,
	}
	err = repo.Fetch(&opts)
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return false, KobraError(GitFetchError, err)
	}

	// now get the local branch reference
	refLocal, err := repo.Head()
	if err != nil {
		return false, KobraError(GitHeadError, err)
	}
	klog.Debugf("Local Head: %s - %s", refLocal.Hash().String(), refLocal.Name())

	// find remote
	remote, err := repo.Remote(GitOrigin)
	if err != nil {
		return false, KobraError(GitRemoteError, err)
	}

	// list all remote refs
	refs, err := remote.List(&git.ListOptions{Auth: auth})
	if err != nil {
		return false, KobraError(GitRemoteHeadError, err)
	}

	// look for remote reference on the same branch
	var refRemote *plumbing.Reference
	for _, ref := range refs {
		if ref.Name() == refLocal.Name() {
			refRemote = ref
			klog.Debugf("Remote Head: %s - %s", refRemote.Hash().String(), refRemote.Name())
			break
		}
	}

	if refRemote == nil {
		// there's no remote branch yet, so go ahead
		return true, KobraError(GitRemoteRefError)
	}

	behindCount, err := revListCount(repo, refLocal, refRemote)
	if err != nil {
		return false, KobraError(GitRevHistoryError)
	}
	klog.Debugf("behindCount: %d", behindCount)

	aheadCount, err := revListCount(repo, refRemote, refLocal)
	if err != nil {
		return false, KobraError(GitRevHistoryError)
	}
	klog.Debugf("aheadCount: %d", aheadCount)

	if behindCount == 0 && aheadCount == 0 {
		klog.Infof("Local branch is up-to-date, we're good to go !")
		return true, nil
	}

	if behindCount == 0 && aheadCount > 0 {
		klog.Infof("Local branch is ahead, we're good to go !")
		return true, nil
	}

	if behindCount > 0 && aheadCount == 0 {
		klog.Infof("Remote branch is ahead, you should pull and merge before going further.")
		return false, nil
	}

	// failover: behindCount > 0 && aheadCount > 0
	klog.Infof("Local and Remote branches have diverged, you really should pull and merge before going further.")
	return false, nil
}
