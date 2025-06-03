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

type encryptConfig struct {
	UnencryptedSuffix       string
	EncryptedSuffix         string
	UnencryptedRegex        string
	EncryptedRegex          string
	UnencryptedCommentRegex string
	EncryptedCommentRegex   string
	MACOnlyEncrypted        bool
	KeyGroups               []sops.KeyGroup
	GroupThreshold          int
}

type encryptOpts struct {
	Cipher        sops.Cipher
	InputStore    sops.Store
	OutputStore   sops.Store
	InputPath     string
	ReadFromStdin bool
	KeyServices   []keyservice.KeyServiceClient
	encryptConfig
}

type editOpts struct {
	Cipher          sops.Cipher
	InputStore      common.Store
	OutputStore     common.Store
	InputPath       string
	IgnoreMAC       bool
	KeyServices     []keyservice.KeyServiceClient
	DecryptionOrder []string
	ShowMasterKeys  bool
}

type editExampleOpts struct {
	editOpts
	encryptConfig
}

type runEditorUntilOkOpts struct {
	TmpFileName    string
	OriginalHash   []byte
	InputStore     sops.Store
	ShowMasterKeys bool
	Tree           *sops.Tree
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
		"editor mode, for example: `sops my_file.yaml`"
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
		EncryptedSuffix:         config.EncryptedSuffix,
		UnencryptedRegex:        config.UnencryptedRegex,
		EncryptedRegex:          config.EncryptedRegex,
		UnencryptedCommentRegex: config.UnencryptedCommentRegex,
		EncryptedCommentRegex:   config.EncryptedCommentRegex,
		MACOnlyEncrypted:        config.MACOnlyEncrypted,
		Version:                 vers.Version,
		ShamirThreshold:         config.GroupThreshold,
	}
}

func encrypt(opts encryptOpts) (encryptedFile []byte, err error) {
	// Load the file
	var fileBytes []byte
	if opts.ReadFromStdin {
		fileBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, common.NewExitError(fmt.Sprintf("error reading from stdin: %s", err), codes.CouldNotReadInputFile)
		}
	} else {
		fileBytes, err = os.ReadFile(opts.InputPath)
		if err != nil {
			return nil, common.NewExitError(fmt.Sprintf("error reading file: %s", err), codes.CouldNotReadInputFile)
		}
	}
	branches, err := opts.InputStore.LoadPlainFile(fileBytes)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("error unmarshalling file: %s", err), codes.CouldNotReadInputFile)
	}
	if len(branches) < 1 {
		return nil, common.NewExitError("file cannot be completely empty, it must contain at least one document", codes.NeedAtLeastOneDocument)
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
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(opts.KeyServices)
	if len(errs) > 0 {
		err = fmt.Errorf("could not generate data key: %s", errs)
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
		return nil, common.NewExitError(fmt.Sprintf("Could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	return
}

func hashFile(filePath string) ([]byte, error) {
	var result []byte
	file, err := os.Open(filePath)
	if err != nil {
		return result, err
	}
	defer func() {
		_ = file.Close()
	}()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}
	return hash.Sum(result), nil
}

func keyGroups(file string) ([]sops.KeyGroup, error) {
	var ageMasterKeys []keys.MasterKey

	ageKeys, err := age.MasterKeysFromRecipients(os.Getenv("SOPS_AGE_RECIPIENTS"))
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

func shamirThreshold(file string) (int, error) {
	// if c.Int("shamir-secret-sharing-threshold") != 0 {
	// 	return c.Int("shamir-secret-sharing-threshold"), nil
	// }
	// conf, err := loadConfig(c, file, nil)
	// if conf == nil {
	// 	// This takes care of the following two case:
	// 	// 1. No config was provided, or contains no creation rules. Err will be nil and ShamirThreshold will be the default value of 0.
	// 	// 2. We did find a config file, but failed to load it. In that case the calling function will print the error and exit.
	// 	return 0, err
	// }
	// return conf.ShamirThreshold, nil
	return 0, nil
}

func getEncryptConfig(fileName string) (encryptConfig, error) {
	var groups []sops.KeyGroup
	groups, err := keyGroups(fileName)
	if err != nil {
		return encryptConfig{}, err
	}

	var threshold int
	threshold, err = shamirThreshold(fileName)
	if err != nil {
		return encryptConfig{}, err
	}

	return encryptConfig{
		UnencryptedSuffix:       sops.DefaultUnencryptedSuffix,
		EncryptedSuffix:         "",
		UnencryptedRegex:        "",
		EncryptedRegex:          "",
		UnencryptedCommentRegex: "",
		EncryptedCommentRegex:   "",
		MACOnlyEncrypted:        false,
		KeyGroups:               groups,
		GroupThreshold:          threshold,
	}, nil
}

func runEditorUntilOk(opts runEditorUntilOkOpts) error {
	for {
		err := runEditor(opts.TmpFileName)
		if err != nil {
			return common.NewExitError(fmt.Sprintf("Could not run editor: %s", err), codes.NoEditorFound)
		}
		newHash, err := hashFile(opts.TmpFileName)
		if err != nil {
			return common.NewExitError(fmt.Sprintf("Could not hash file: %s", err), codes.CouldNotReadInputFile)
		}
		if bytes.Equal(newHash, opts.OriginalHash) {
			return common.NewExitError("File has not changed, exiting.", codes.FileHasNotBeenModified)
		}
		edited, err := os.ReadFile(opts.TmpFileName)
		if err != nil {
			return common.NewExitError(fmt.Sprintf("Could not read edited file: %s", err), codes.CouldNotReadInputFile)
		}
		newBranches, err := opts.InputStore.LoadPlainFile(edited)
		if err != nil {
			klog.Errorf("Could not load tree, probably due to invalid " +
				"syntax. Press a key to return to the editor, or Ctrl+C to " +
				"exit.")
			_, _ = bufio.NewReader(os.Stdin).ReadByte()
			continue
		}
		if opts.ShowMasterKeys {
			// The file is not actually encrypted, but it contains SOPS
			// metadata
			t, err := opts.InputStore.LoadEncryptedFile(edited)
			if err != nil {
				klog.Errorf("SOPS metadata is invalid. Press a key to " +
					"return to the editor, or Ctrl+C to exit.")
				_, _ = bufio.NewReader(os.Stdin).ReadByte()
				continue
			}
			// Replace the whole tree, because otherwise newBranches would
			// contain the SOPS metadata
			opts.Tree = &t
		}
		opts.Tree.Branches = newBranches
		needVersionUpdated, err := vers.AIsNewerThanB(vers.Version, opts.Tree.Metadata.Version)
		if err != nil {
			return common.NewExitError(fmt.Sprintf("Failed to compare document version %q with program version %q: %v", opts.Tree.Metadata.Version, vers.Version, err), codes.FailedToCompareVersions)
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
		editor, err := lookupAnyEditor("vim", "nano", "vi")
		if err != nil {
			return err
		}
		cmd = exec.Command(editor, path)
	} else {
		parts, err := shlex.Split(editor)
		if err != nil {
			return fmt.Errorf("invalid $%s: %s", envVar, editor)
		}
		parts = append(parts, path)
		cmd = exec.Command(parts[0], parts[1:]...)
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
	return "", fmt.Errorf("no editor available: sops attempts to use the editor defined in the SOPS_EDITOR or EDITOR environment variables, and if that's not set defaults to any of %s, but none of them could be found", strings.Join(editorNames, ", "))
}

func editExample(opts editExampleOpts) ([]byte, error) {
	fileBytes := opts.InputStore.EmitExample()
	branches, err := opts.InputStore.LoadPlainFile(fileBytes)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("Error unmarshalling file: %s", err), codes.CouldNotReadInputFile)
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
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(opts.KeyServices)
	if len(errs) > 0 {
		return nil, common.NewExitError(fmt.Sprintf("Error encrypting the data key with one or more master keys: %s", errs), codes.CouldNotRetrieveKey)
	}

	return editTree(opts.editOpts, &tree, dataKey)
}

func edit(opts editOpts) ([]byte, error) {
	// Load the file
	tree, err := common.LoadEncryptedFileWithBugFixes(common.GenericDecryptOpts{
		Cipher:      opts.Cipher,
		InputStore:  opts.InputStore,
		InputPath:   opts.InputPath,
		IgnoreMAC:   opts.IgnoreMAC,
		KeyServices: opts.KeyServices,
	})
	if err != nil {
		return nil, err
	}
	// Decrypt the file
	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:          opts.Cipher,
		IgnoreMac:       opts.IgnoreMAC,
		Tree:            tree,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
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
		return nil, common.NewExitError(fmt.Sprintf("could not create temporary directory: %s", err), codes.CouldNotWriteOutputFile)
	}
	defer func() {
		_ = os.RemoveAll(tmpdir)
	}()

	tmpfile, err := os.Create(filepath.Join(tmpdir, filepath.Base(opts.InputPath)))
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("could not create temporary file: %s", err), codes.CouldNotWriteOutputFile)
	}
	// Ensure that in any case, the temporary file is always closed.
	defer func() {
		_ = tmpfile.Close()
	}()

	tmpfileName := tmpfile.Name()

	// Write to temporary file
	var out []byte
	if opts.ShowMasterKeys {
		out, err = opts.OutputStore.EmitEncryptedFile(*tree)
	} else {
		out, err = opts.OutputStore.EmitPlainFile(tree.Branches)
	}
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	_, err = tmpfile.Write(out)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("could not write output file: %s", err), codes.CouldNotWriteOutputFile)
	}

	// Compute file hash to detect if the file has been edited
	origHash, err := hashFile(tmpfileName)
	if err != nil {
		return nil, common.NewExitError(fmt.Sprintf("could not hash file: %s", err), codes.CouldNotReadInputFile)
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
		InputStore: opts.InputStore, OriginalHash: origHash, TmpFileName: tmpfileName,
		ShowMasterKeys: opts.ShowMasterKeys, Tree: tree})
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
		return nil, common.NewExitError(fmt.Sprintf("could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	return encryptedFile, nil
}

func keyservices() (svcs []keyservice.KeyServiceClient) {
	svcs = append(svcs, keyservice.NewLocalClient())
	return
}

func loadStoresConfig() (*config.StoresConfig, error) {
	return config.NewStoresConfig(), nil

	// configPath := context.GlobalString("config")
	// if configPath == "" {
	// 	// Ignore config not found errors returned from findConfigFile since the config file is not mandatory
	// 	foundPath, err := findConfigFile()
	// 	if err != nil {
	// 		return config.NewStoresConfig(), nil
	// 	}
	// 	configPath = foundPath
	// }
	// return config.LoadStoresConfig(configPath)
}

func inputStore(path string) (common.Store, error) {
	storesConf, err := loadStoresConfig()
	if err != nil {
		return nil, err
	}
	return common.DefaultStoreForPathOrFormat(storesConf, path, ""), nil
}

func outputStore(path string) (common.Store, error) {
	storesConf, err := loadStoresConfig()
	if err != nil {
		return nil, err
	}
	// if context.IsSet("indent") {
	// 	indent := context.Int("indent")
	// 	storesConf.YAML.Indent = indent
	// 	storesConf.JSON.Indent = indent
	// 	storesConf.JSONBinary.Indent = indent
	// }

	return common.DefaultStoreForPathOrFormat(storesConf, path, ""), nil
}

func decryptionOrder(decryptionOrder string) ([]string, error) {
	if decryptionOrder == "" {
		return sops.DefaultDecryptionOrder, nil
	}
	orderList := strings.Split(decryptionOrder, ",")
	unique := make(map[string]struct{})
	for _, v := range orderList {
		if _, ok := unique[v]; ok {
			return nil, common.NewExitError(fmt.Sprintf("Duplicate decryption key type: %s", v), codes.DuplicateDecryptionKeyType)
		}
		unique[v] = struct{}{}
	}
	return orderList, nil
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

	inputStore, err := inputStore(fileName)
	if err != nil {
		return err
	}
	outputStore, err := outputStore(fileName)
	if err != nil {
		return err
	}
	svcs := keyservices()

	order, err := decryptionOrder("")
	if err != nil {
		return err
	}

	var output []byte
	_, statErr := os.Stat(fileName)
	fileExists := statErr == nil
	opts := editOpts{
		OutputStore:     outputStore,
		InputStore:      inputStore,
		InputPath:       fileName,
		Cipher:          aes.NewCipher(),
		KeyServices:     svcs,
		DecryptionOrder: order,
		IgnoreMAC:       false,
		ShowMasterKeys:  false,
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
	f, err := os.Create(fileName)
	if err != nil {
		return common.NewExitError(fmt.Sprintf("could not open in-place file for writing: %s", err), codes.CouldNotWriteOutputFile)
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

	inputStore, err := inputStore(fileName)
	if err != nil {
		return err
	}
	outputStore, err := outputStore(fileName)
	if err != nil {
		return err
	}
	svcs := keyservices()

	encConfig, err := getEncryptConfig(fileName)
	if err != nil {
		return err
	}
	output, err := encrypt(encryptOpts{
		OutputStore:   outputStore,
		InputStore:    inputStore,
		InputPath:     fileName,
		ReadFromStdin: false,
		Cipher:        aes.NewCipher(),
		KeyServices:   svcs,
		encryptConfig: encConfig,
	})

	if err != nil {
		return err
	}

	// We open the file *after* the operations on the tree have been
	// executed to avoid truncating it when there's errors
	f, err := os.Create(fileName)
	if err != nil {
		return common.NewExitError(fmt.Sprintf("could not open in-place file for writing: %s", err), codes.CouldNotWriteOutputFile)
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
