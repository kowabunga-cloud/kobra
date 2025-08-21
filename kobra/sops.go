/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Freely inspired and vastly copy/pasted from upstream github.com/getsops/sops/cmd,
 * released under Mozilla Public License Version 2.0.
 */

package kobra

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores"
	vers "github.com/getsops/sops/v3/version"

	"github.com/google/shlex"
	"github.com/mitchellh/go-wordwrap"

	exec "golang.org/x/sys/execabs"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	SopsReadFileErr      = "error reading file: %s"
	SopsUnmarshalErr     = "error unmarshalling file: %s"
	SopsEmptyFileErr     = "file cannot be completely empty, it must contain at least one document"
	SopsGenerateKeyErr   = "could not generate data key: %s"
	SopsMarshalTreeErr   = "could not marshal tree: %s"
	SopsNoEditorErr      = "could not run editor: %s"
	SopsHashErr          = "could not hash file: %s"
	SopsUnchangedFileErr = "file has not changed, exiting."
	SopsReadErr          = "could not read edited file: %s"
	SopsComparisonErr    = "failed to compare document version %q with program version %q: %v"
	SopsEditorErr        = "no editor available: sops attempts to use the editor defined in the SOPS_EDITOR or EDITOR environment variables, and if that's not set defaults to any of %s, but none of them could be found"
	SopsEncryptErr       = "error encrypting the data key with one or more master keys: %s"
	SopsInPlaceErr       = "could not open in-place file for writing: %s"
	SopsCreateDirErr     = "could not create temporary directory: %s"
	SopsCreateFileErr    = "could not create temporary file: %s"
	SopsWriteErr         = "could not write output file: %s"
)

type encryptConfig struct {
	UnencryptedSuffix string
	KeyGroups         []sops.KeyGroup
}

type encryptOpts struct {
	Cipher      sops.Cipher
	InputStore  sops.Store
	OutputStore sops.Store
	InputPath   string
	encryptConfig
}

type editOpts struct {
	Cipher      sops.Cipher
	InputStore  common.Store
	OutputStore common.Store
	InputPath   string
}

type editExampleOpts struct {
	editOpts
	encryptConfig
}

type runEditorUntilOkOpts struct {
	TmpFileName  string
	OriginalHash []byte
	InputStore   sops.Store
	Tree         *sops.Tree
}

type fileAlreadyEncryptedError struct{}

func (err *fileAlreadyEncryptedError) Error() string {
	return "File already encrypted"
}

func (err *fileAlreadyEncryptedError) UserError() string {
	message := "The file you have provided contains a top-level entry called " +
		"'" + stores.SopsMetadataKey + "', or for flat file formats top-level entries starting with " +
		"'" + stores.SopsMetadataKey + "_'. This is generally due to the file already being encrypted. " +
		"SOPS uses a top-level entry called '" + stores.SopsMetadataKey + "' to store the metadata " +
		"required to decrypt the file. For this reason, SOPS can not " +
		"encrypt files that already contain such an entry.\n\n" +
		"If this is an unencrypted file, rename the '" + stores.SopsMetadataKey + "' entry.\n\n" +
		"If this is an encrypted file and you want to edit it, use the " +
		"editor mode, for example: `kobra secrets edit my_file.yaml`"
	return wordwrap.WrapString(message, 75)
}

func ensureNoMetadata(opts encryptOpts, branch sops.TreeBranch) error {
	if opts.OutputStore.HasSopsTopLevelKey(branch) {
		return &fileAlreadyEncryptedError{}
	}
	return nil
}

func metadataFromEncryptionConfig(config encryptConfig) sops.Metadata {
	return sops.Metadata{
		KeyGroups:               config.KeyGroups,
		UnencryptedSuffix:       config.UnencryptedSuffix,
		EncryptedSuffix:         "",
		UnencryptedRegex:        "",
		EncryptedRegex:          "",
		UnencryptedCommentRegex: "",
		EncryptedCommentRegex:   "",
		MACOnlyEncrypted:        false,
		Version:                 vers.Version,
		ShamirThreshold:         0,
	}
}

func encrypt(opts encryptOpts) (encryptedFile []byte, err error) {
	// Load the file
	fileBytes, err := os.ReadFile(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf(SopsReadFileErr, err)
	}

	branches, err := opts.InputStore.LoadPlainFile(fileBytes)
	if err != nil {
		return nil, fmt.Errorf(SopsUnmarshalErr, err)
	}
	if len(branches) < 1 {
		return nil, fmt.Errorf("%s", SopsEmptyFileErr)
	}
	if err := ensureNoMetadata(opts, branches[0]); err != nil {
		return nil, common.NewExitError(err, codes.FileAlreadyEncrypted)
	}
	path, err := filepath.Abs(opts.InputPath)
	if err != nil {
		return nil, err
	}
	tree := sops.Tree{
		Branches: branches,
		Metadata: metadataFromEncryptionConfig(opts.encryptConfig),
		FilePath: path,
	}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(keyservices())
	if len(errs) > 0 {
		err = fmt.Errorf(SopsGenerateKeyErr, errs)
		return nil, err
	}

	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  opts.Cipher,
	})
	if err != nil {
		return nil, err
	}

	encryptedFile, err = opts.OutputStore.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf(SopsMarshalTreeErr, err)
	}
	return
}

func hashFile(filePath string) ([]byte, error) {
	var result []byte
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return result, err
	}
	defer func() {
		_ = file.Close()
	}()

	hash := sha256.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return result, err
	}

	return hash.Sum(result), nil
}

func keyGroups(file string) ([]sops.KeyGroup, error) {
	var ageMasterKeys []keys.MasterKey

	ageKeys, err := age.MasterKeysFromRecipients(os.Getenv(SopsAgeRecipientsEnv))
	if err != nil {
		return nil, err
	}
	for _, k := range ageKeys {
		ageMasterKeys = append(ageMasterKeys, k)
	}

	var group sops.KeyGroup
	group = append(group, ageMasterKeys...)
	return []sops.KeyGroup{group}, nil
}

func getEncryptConfig(fileName string) (encryptConfig, error) {
	groups, err := keyGroups(fileName)
	if err != nil {
		return encryptConfig{}, err
	}

	return encryptConfig{
		UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
		KeyGroups:         groups,
	}, nil
}

func runEditorUntilOk(opts runEditorUntilOkOpts) error {
	for {
		err := runEditor(opts.TmpFileName)
		if err != nil {
			return fmt.Errorf(SopsNoEditorErr, err)
		}
		newHash, err := hashFile(opts.TmpFileName)
		if err != nil {
			return fmt.Errorf(SopsHashErr, err)
		}
		if bytes.Equal(newHash, opts.OriginalHash) {
			return fmt.Errorf("%s", SopsUnchangedFileErr)
		}
		edited, err := os.ReadFile(opts.TmpFileName)
		if err != nil {
			return fmt.Errorf(SopsReadErr, err)
		}
		newBranches, err := opts.InputStore.LoadPlainFile(edited)
		if err != nil {
			klog.Errorf("Could not load tree, probably due to invalid " +
				"syntax. Press a key to return to the editor, or Ctrl+C to " +
				"exit.")
			_, _ = bufio.NewReader(os.Stdin).ReadByte()
			continue
		}
		opts.Tree.Branches = newBranches
		needVersionUpdated, err := vers.AIsNewerThanB(vers.Version, opts.Tree.Metadata.Version)
		if err != nil {
			return fmt.Errorf(SopsComparisonErr, opts.Tree.Metadata.Version, vers.Version, err)
		}
		if needVersionUpdated {
			opts.Tree.Metadata.Version = vers.Version
		}
		if opts.Tree.Metadata.MasterKeyCount() == 0 {
			klog.Errorf("No master keys were provided, so sops can't " +
				"encrypt the file. Press a key to return to the editor, or " +
				"Ctrl+C to exit.")
			_, _ = bufio.NewReader(os.Stdin).ReadByte()
			continue
		}
		break
	}
	return nil
}

func runEditor(path string) error {
	envVar := "SOPS_EDITOR"
	editor := os.Getenv(envVar)
	if editor == "" {
		envVar = "EDITOR"
		editor = os.Getenv(envVar)
	}
	var cmd *exec.Cmd
	if editor == "" {
		editor, err := lookupAnyEditor("nano", "emacs", "vim", "vi")
		if err != nil {
			return err
		}
		cmd = exec.Command(editor, path) // #nosec G204
	} else {
		parts, err := shlex.Split(editor)
		if err != nil {
			return fmt.Errorf("invalid $%s: %s", envVar, editor)
		}
		parts = append(parts, path)
		cmd = exec.Command(parts[0], parts[1:]...) // #nosec G204
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func lookupAnyEditor(editorNames ...string) (editorPath string, err error) {
	for _, editorName := range editorNames {
		editorPath, err = exec.LookPath(editorName)
		if err == nil {
			return editorPath, nil
		}
	}
	return "", fmt.Errorf(SopsEditorErr, strings.Join(editorNames, ", "))
}

func editExample(opts editExampleOpts) ([]byte, error) {
	fileBytes := opts.InputStore.EmitExample()
	branches, err := opts.InputStore.LoadPlainFile(fileBytes)
	if err != nil {
		return nil, fmt.Errorf(SopsUnmarshalErr, err)
	}
	path, err := filepath.Abs(opts.InputPath)
	if err != nil {
		return nil, err
	}
	tree := sops.Tree{
		Branches: branches,
		Metadata: metadataFromEncryptionConfig(opts.encryptConfig),
		FilePath: path,
	}

	// Generate a data key
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(keyservices())
	if len(errs) > 0 {
		return nil, fmt.Errorf(SopsEncryptErr, errs)
	}

	return editTree(opts.editOpts, &tree, dataKey)
}

func edit(opts editOpts) ([]byte, error) {
	// Load the file
	tree, err := common.LoadEncryptedFileWithBugFixes(common.GenericDecryptOpts{
		Cipher:      opts.Cipher,
		InputStore:  opts.InputStore,
		InputPath:   opts.InputPath,
		IgnoreMAC:   false,
		KeyServices: keyservices(),
	})
	if err != nil {
		return nil, err
	}
	// Decrypt the file
	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:          opts.Cipher,
		IgnoreMac:       false,
		Tree:            tree,
		KeyServices:     keyservices(),
		DecryptionOrder: sops.DefaultDecryptionOrder,
	})
	if err != nil {
		return nil, err
	}

	return editTree(opts, tree, dataKey)
}

func editTree(opts editOpts, tree *sops.Tree, dataKey []byte) ([]byte, error) {
	// Create temporary file for editing
	tmpdir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, fmt.Errorf(SopsCreateDirErr, err)
	}
	defer func() {
		_ = os.RemoveAll(tmpdir)
	}()

	tmpfile, err := os.Create(filepath.Clean(filepath.Join(tmpdir, filepath.Base(opts.InputPath))))
	if err != nil {
		return nil, fmt.Errorf(SopsCreateFileErr, err)
	}
	// Ensure that in any case, the temporary file is always closed.
	defer func() {
		_ = tmpfile.Close()
	}()

	tmpfileName := tmpfile.Name()

	// Write to temporary file
	out, err := opts.OutputStore.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf(SopsMarshalTreeErr, err)
	}
	_, err = tmpfile.Write(out)
	if err != nil {
		return nil, fmt.Errorf(SopsWriteErr, err)
	}

	// Compute file hash to detect if the file has been edited
	origHash, err := hashFile(tmpfileName)
	if err != nil {
		return nil, fmt.Errorf(SopsHashErr, err)
	}

	// Close the temporary file, so that an editor can open it.
	// We need to do this because some editors (e.g. VSCode) will refuse to
	// open a file on Windows due to the Go standard library not opening
	// files with shared delete access.
	if err := tmpfile.Close(); err != nil {
		return nil, err
	}

	// Let the user edit the file
	err = runEditorUntilOk(runEditorUntilOkOpts{
		InputStore:   opts.InputStore,
		OriginalHash: origHash,
		TmpFileName:  tmpfileName,
		Tree:         tree,
	})
	if err != nil {
		return nil, err
	}

	// Encrypt the file
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey, Tree: tree, Cipher: opts.Cipher,
	})
	if err != nil {
		return nil, err
	}

	// Output the file
	encryptedFile, err := opts.OutputStore.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, fmt.Errorf(SopsMarshalTreeErr, err)
	}
	return encryptedFile, nil
}

func keyservices() []keyservice.KeyServiceClient {
	return []keyservice.KeyServiceClient{
		keyservice.NewLocalClient(),
	}
}

func defaultStore(path string) common.Store {
	return common.DefaultStoreForPathOrFormat(config.NewStoresConfig(), path, "")
}

func SopsViewFile(cfg *KobraConfig, file string) error {
	keyFile, err := secretsSopsSetEnv()
	if err != nil {
		return err
	}
	if keyFile != "" {
		defer func() {
			_ = os.Remove(keyFile)
		}()
	}

	fileName, err := filepath.Abs(file)
	if err != nil {
		return err
	}

	data, err := decrypt.File(fileName, "")
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(data)

	return err
}

func SopsEditFile(cfg *KobraConfig, file string) error {
	keyFile, err := secretsSopsSetEnv()
	if err != nil {
		return err
	}
	if keyFile != "" {
		defer func() {
			_ = os.Remove(keyFile)
		}()
	}

	fileName, err := filepath.Abs(file)
	if err != nil {
		return err
	}

	var output []byte
	_, statErr := os.Stat(fileName)
	fileExists := statErr == nil
	opts := editOpts{
		OutputStore: defaultStore(fileName),
		InputStore:  defaultStore(fileName),
		InputPath:   fileName,
		Cipher:      aes.NewCipher(),
	}
	if fileExists {
		output, err = edit(opts)
		if err != nil {
			return err
		}
	} else {
		// File doesn't exist, edit the example file instead
		encConfig, err := getEncryptConfig(fileName)
		if err != nil {
			return err
		}
		output, err = editExample(editExampleOpts{
			editOpts:      opts,
			encryptConfig: encConfig,
		})
		if err != nil {
			return err
		}
	}

	// We open the file *after* the operations on the tree have been
	// executed to avoid truncating it when there's errors
	f, err := os.Create(filepath.Clean(fileName))
	if err != nil {
		return fmt.Errorf(SopsInPlaceErr, err)
	}
	defer func() {
		_ = f.Close()
	}()
	_, err = f.Write(output)
	if err != nil {
		return err
	}
	klog.Infof("File written successfully")
	return nil
}

func SopsEncryptFile(cfg *KobraConfig, file string) error {
	keyFile, err := secretsSopsSetEnv()
	if err != nil {
		return err
	}
	if keyFile != "" {
		defer func() {
			_ = os.Remove(keyFile)
		}()
	}

	fileName, err := filepath.Abs(file)
	if err != nil {
		return err
	}

	encConfig, err := getEncryptConfig(fileName)
	if err != nil {
		return err
	}
	output, err := encrypt(encryptOpts{
		OutputStore:   defaultStore(fileName),
		InputStore:    defaultStore(fileName),
		InputPath:     fileName,
		Cipher:        aes.NewCipher(),
		encryptConfig: encConfig,
	})

	if err != nil {
		return err
	}

	// We open the file *after* the operations on the tree have been
	// executed to avoid truncating it when there's errors
	f, err := os.Create(filepath.Clean(fileName))
	if err != nil {
		return fmt.Errorf(SopsInPlaceErr, err)
	}
	defer func() {
		_ = f.Close()
	}()
	_, err = f.Write(output)
	if err != nil {
		return err
	}

	klog.Infof("File written successfully")
	return nil
}
