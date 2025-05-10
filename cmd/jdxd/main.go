package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/whacked/jdxd/pkg/jdxd"
	_ "github.com/whacked/jdxd/pkg/jdxd"

	"github.com/fatih/color"
	"github.com/spf13/pflag"
)

const (
	ProgramName = "jdxd"
)

// JDXDCliConfig represents the complete configuration needed to run jdxd
type JDXDCliConfig struct {
	// Core transformation configuration
	TransformerSource string
	InputFile        string
	InputSchema      string
	OutputSchema     string
	IsStdin        bool

	// Shell completion generation
	GenerateShellCompletions string
}


var SupportedShells = map[string]bool{
	"bash":       true,
	"zsh":        true,
	"fish":       true,
	"powershell": true,
}

type ConfigValidationError struct {
	Reason string
	Field  string
	Detail string
}

func (e ConfigValidationError) Error() string {
	return fmt.Sprintf("invalid config: %s (field: %s, detail: %s)", e.Reason, e.Field, e.Detail)
}

//go:embed schemas/FileToJsonataTransformerMapping.schema.json
var fileToJsonataTransformerMapping embed.FS

const fileToJsonataTransformerEmbedPath = "schemas/FileToJsonataTransformerMapping.schema.json"

//go:embed schemas/FileToValidatedInOutTransformerMapping.schema.json
var fileToValidatedInOutTransformerMapping embed.FS

const fileToValidatedInOutTransformerEmbedPath = "schemas/FileToValidatedInOutTransformerMapping.schema.json"

//go:embed schemas/InXfmOutSpec.schema.json
var InXfmOutSpec embed.FS

const InXfmOutSpecEmbedPath = "schemas/InXfmOutSpec.schema.json"

// getMapKeys returns a slice of keys from a map
// somehow we expect this to be in the "maps" package but
// on my go1.22 it doesn't work
func getMapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func removeCStyleComments(input string) string { // jsonata-go doesn't parse comments now
	re := regexp.MustCompile(`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/`)
	return re.ReplaceAllString(input, "")
}

func readInOutProcessorSpec(sourceFile string) *jdxd.InXfmOutSpecSchemaJson {
	jsonStr := jdxd.RenderJsonnetFile(sourceFile)
	var toValidate interface{} // InXfmOutSpecSchemaJson
	if err := json.Unmarshal([]byte(jsonStr), &toValidate); err != nil {
		fmt.Fprintf(os.Stderr, "Error unmarshaling %s: %v\n", sourceFile, err)
	}
	var out *jdxd.InXfmOutSpecSchemaJson
	validator := jdxd.LoadValidator(InXfmOutSpec, InXfmOutSpecEmbedPath)
	if err := validator.Validate(toValidate); err != nil {
		fmt.Fprintf(os.Stderr, "Error validating in out processor spec %s:\n%v\n", sourceFile, err)
		// fmt.Fprintf(os.Stderr, "[input]:\n%s", jsonStr)
		log.Fatal("BYE")
	} else {
		var toValidate jdxd.InXfmOutSpecSchemaJson
		if err := json.Unmarshal([]byte(jsonStr), &toValidate); err != nil {
			fmt.Fprintf(os.Stderr, "Error unmarshaling %s: %v\n", sourceFile, err)
		}
		if toValidate.Jsonata == nil {
			log.Fatalf("Jsonata is currently required in %s", sourceFile)
		}
		cleanedCode := removeCStyleComments(*toValidate.Jsonata)
		out = &jdxd.InXfmOutSpecSchemaJson{
			In:      toValidate.In,
			Jsonata: &cleanedCode,
			Out:     toValidate.Out,
		}
	}
	return out
}

func readDirectoryProcessorSpec(sourceFile string) map[string]*jdxd.InXfmOutSpecSchemaJson {
	jsonStr := jdxd.RenderJsonnetFile(sourceFile)

	var toValidate map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &toValidate); err != nil {
		jdxd.DebugLog(fmt.Sprintf("1. FAILED TO UNMARSHAL JSON FROM %s", sourceFile))
		panic(err)
	}

	var out map[string]*jdxd.InXfmOutSpecSchemaJson = make(map[string]*jdxd.InXfmOutSpecSchemaJson)
	fileToJsonnetTransformerMappingValidator := jdxd.LoadValidator(fileToJsonataTransformerMapping, fileToJsonataTransformerEmbedPath)

	if err := fileToJsonnetTransformerMappingValidator.Validate(toValidate); err != nil {
		jdxd.DebugLog(fmt.Sprintf("2. FAILED TO VALIDATE JSON FROM %s", sourceFile))
		fmt.Fprintf(
			os.Stderr,
			"Error validating FileToJsonataTransformerMapping: %v\n",
			err,
		)
	} else {
		jdxd.DebugLog(fmt.Sprintf("2. VALIDATED JSON FROM %s", sourceFile))
		for pattern, transformerCode := range toValidate {
			if transformerCode == "" {
				out[pattern] = nil
				continue
			}
			out[pattern] = &jdxd.InXfmOutSpecSchemaJson{}
			cleanedCode := removeCStyleComments(transformerCode.(string))
			out[pattern].Jsonata = &cleanedCode
		}
	}

	fileToValidatedInOutTransformerMappingValidator := jdxd.LoadValidator(fileToValidatedInOutTransformerMapping, fileToValidatedInOutTransformerEmbedPath)

	if err := fileToValidatedInOutTransformerMappingValidator.Validate(toValidate); err != nil {
		jdxd.DebugLog(fmt.Sprintf("3. FAILED TO VALIDATE JSON FROM %s", sourceFile))
		fmt.Println(err)
	} else {
		jdxd.DebugLog(fmt.Sprintf("3. VALIDATED JSON FROM %s", sourceFile))
		for pattern, ioSpec := range toValidate {
			if ioSpec == nil {
				out[pattern] = nil
				continue
			}
			// fmt.Println(ioSpec)
			mappedValue, ok := ioSpec.(map[string]interface{})
			if !ok {
				// Handle the error, the assertion failed
				panic("ioSpec is not a map[string]interface{}")
			}
			cleanedCode := removeCStyleComments(mappedValue["transformer"].(string))
			out[pattern] = &jdxd.InXfmOutSpecSchemaJson{
				In:      mappedValue["inputSchema"].(map[string]interface{}),
				Jsonata: &cleanedCode,
				Out:     mappedValue["outputSchema"].(map[string]interface{}),
			}

		}
	}

	return out
}

func getTransformerSpec(transformerMap map[string]*jdxd.InXfmOutSpecSchemaJson, filePath string) *jdxd.InXfmOutSpecSchemaJson {
	for pattern, transformerSpec := range transformerMap {
		matched, _ := regexp.MatchString(pattern, filePath)
		if matched {
			return transformerSpec
		}
	}
	return nil
}

func getJsonRecordFiles(rootDirectory string) []string {
	matches := []string{}
	extensions := []string{".json", ".jsonl"}

	err := filepath.Walk(rootDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden files and directories
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") {
			if info.IsDir() {
				return filepath.SkipDir // Skip the entire directory if it's hidden
			}
			return nil // Skip hidden files but continue walking
		}

		for _, ext := range extensions {
			if filepath.Ext(path) == ext {
				matches = append(matches, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	return matches
}

func transformDataStreamSource(
	dataSource string, transformCode string,
	inputSchema string, outputSchema string,
	transformCodeKnownFormat string,
	transformerFilePath string,
) {
	recordTransformer := jdxd.MakeRecordTransformer(transformCode, transformCodeKnownFormat, transformerFilePath)
	if recordTransformer.Transform == nil {
		fmt.Fprintf(os.Stderr, "Failed to compile transformer code: %s\n", transformCode)
		return
	}

	var dataSourceSubstring string
	if len(dataSource) > 300 {
		dataSourceSubstring = dataSource[:200]
	} else {
		dataSourceSubstring = dataSource
	}
	jdxd.DebugLog(color.CyanString(fmt.Sprintf("Transforming data source: %s...\nwith transform: %s", dataSourceSubstring, jdxd.ColorizeByTransformerLanguage(recordTransformer.Type, transformCode))))

	var inputValidator jdxd.JsonDataValidatorFunc
	var outputValidator jdxd.JsonDataValidatorFunc
	if inputSchema != "" && inputSchema != "null" {
		jsonStr := jdxd.RenderJsonnetFile(inputSchema)
		inputValidator = jdxd.MakeRecordValidatorFromJsonString("input-schema", jsonStr)
	}
	if outputSchema != "" && outputSchema != "null" {
		jsonStr := jdxd.RenderJsonnetFile(outputSchema)
		outputValidator = jdxd.MakeRecordValidatorFromJsonString("output-schema", jsonStr)
	}

	if dataSource == "-" {
		jdxd.TransformDataStream(bufio.NewScanner(os.Stdin), inputValidator, outputValidator, recordTransformer)
	} else if jdxd.IsDirectory(dataSource) {
		for _, filePath := range getJsonRecordFiles(dataSource) {
			jdxd.TransformFile(filePath, inputValidator, outputValidator, recordTransformer)
		}
	} else {
		jdxd.TransformFile(dataSource, inputValidator, outputValidator, recordTransformer)
	}
}

func processDirectory(rootDirectory string, directoryProcessorSpecFile string) {

	/*
		globs into a data directory for json files
		then using the spec file that contains <file-name-match-pattern>:<jsonata-transformer>
		it applies the transformer to each of the matched files


		dataSource := os.Args[1] // dataSource := filepath.Join(os.Getenv("CLOUDSYNC"), "main/analysis/DATA/fitbit/MyFitbitData")
		specFile := os.Args[2]   // specFile := "../dxd/registry/com.fitbit/2023-11-11-iospec.jsonnet"

		if fileInfo, err := os.Stat(dataSource); err != nil {
			fmt.Println("Error reading data source:", err)
		} else if fileInfo.IsDir() {
			processDirectory(dataSource, specFile)
		} else {

		}

	*/

	matches := getJsonRecordFiles(rootDirectory)
	fmt.Println("Matches:", len(matches))
	for _, match := range matches {
		fmt.Printf("Match: %s\n", match)
	}

	transformerMap := readDirectoryProcessorSpec(directoryProcessorSpecFile)

	jdxd.DebugLog(fmt.Sprintf("Found %d files in %s", len(matches), rootDirectory))

	numProcessed := 0
	for _, filePath := range matches {

		transformerSpec := getTransformerSpec(transformerMap, filePath)
		if transformerSpec == nil {
			jdxd.DebugLog(fmt.Sprintf("No transformer found for file: %s", filePath))
			continue
		}

		jdxd.DebugLog(fmt.Sprintf("Processing file: %s", filePath))
		jdxd.DebugLog(fmt.Sprintf("Transformer code: %v", transformerSpec))

		jsonContent, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading file: %v", err)
			continue
		}

		var jsonData interface{}
		err = json.Unmarshal(jsonContent, &jsonData)
		if err != nil {
			jdxd.DebugLog(fmt.Sprintf("Error unmarshaling JSON: %v", err))
			continue
		}

		transformer := jdxd.MakeRecordTransformer(*transformerSpec.Jsonata, jdxd.JSONATA_TRANSFORMER, directoryProcessorSpecFile)
		result := jdxd.TransformRecord(&jsonData, nil, nil, transformer)
		jsonified := jdxd.JsonDataToString(result)

		fmt.Fprintf(os.Stdout, "%s\n", jsonified)
		numProcessed++

		// save to /tmp/transformed.json
		// err = os.WriteFile("/tmp/transformed.json", jsonified, 0644)

		break
	}

	jdxd.DebugLog(fmt.Sprintf("Processed %d files", numProcessed))
}

func parseArgs(args []string) (*JDXDCliConfig, error) {
	cfg := &JDXDCliConfig{}
	// Check if any flag-style arg exists
	hasFlags := false
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && len(arg) > 1 && arg != "-" {
			hasFlags = true
			break
		}
	}

	if !hasFlags {
		// Handle positional args manually
		switch len(args) {
		case 1:
			cfg.TransformerSource = args[0]
			cfg.InputFile = "-"
			cfg.IsStdin = true
		case 2:
			cfg.InputFile = args[0]
			cfg.TransformerSource = args[1]
		default:
			return nil, fmt.Errorf("invalid number of positional args: need a transformer source and input file or stdin")
		}
		return cfg, nil
	}

	// Use pflag to parse flags
	fs := pflag.NewFlagSet(ProgramName, pflag.ContinueOnError)
	transformer := fs.StringP("transformer", "t", "", "path to transformer file, or transformer code")
	input := fs.StringP("input-data", "d", "", "path to input file, or '-' for stdin")
	inSchema := fs.StringP("input-schema", "i", "", "path to input schema file, or schema as json(net) string")
	outSchema := fs.StringP("output-schema", "o", "", "path to output schema file, or schema as json(net) string")
	completions := fs.String("completions", "",
		"generate shell completions for the given shell ("+strings.Join(getMapKeys(SupportedShells), ", ")+")",
	)

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Positional args not allowed in flag mode
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("positional args not allowed with flags")
	}

	cfg.TransformerSource = *transformer
	cfg.InputFile = *input
	cfg.InputSchema = *inSchema
	cfg.OutputSchema = *outSchema
	cfg.GenerateShellCompletions = *completions

	if cfg.GenerateShellCompletions == "" && cfg.InputFile == "" {
		cfg.InputFile = "-"
	}

	// Handle stdin mode for flag-based input
	if cfg.InputFile == "-" {
		cfg.IsStdin = true
	}

	return cfg, nil
}

// IsValid returns an error if the configuration is invalid
func (c *JDXDCliConfig) IsValid() error {
	// Shell completions mode
	if c.GenerateShellCompletions != "" {
		if !SupportedShells[c.GenerateShellCompletions] {
			return ConfigValidationError{
				Reason: "unsupported shell",
				Field:  "GenerateShellCompletions",
				Detail: c.GenerateShellCompletions,
			}
		}
	} else {
		// Must have a transformer source
		if c.TransformerSource == "" {
			return ConfigValidationError{
				Reason: "missing required field",
				Field:  "TransformerSource",
				Detail: "need at least a transformer as input",
			}
		}
		
		if _, err := os.Stat(c.TransformerSource); os.IsNotExist(err) {
			return ConfigValidationError{
				Reason: "file not found",
				Field:  "TransformerSource",
				Detail: c.TransformerSource,
			}
		}

		// STDIN mode validation
		if c.IsStdin {
			if c.InputFile != "-" {
				return ConfigValidationError{
					Reason: "invalid input file",
					Field:  "InputFile",
					Detail: "stdin mode requires input file to be '-'",
				}
			}
		}
	}
	return nil
}

func main() {
	COLORIZED_PROGRAM_NAME := color.HiBlueString(os.Args[0])
	fmt.Println("HELLO", COLORIZED_PROGRAM_NAME)

	// Parse command line arguments
	config, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Validate configuration
	if err := config.IsValid(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Special case for directory processing
	isDirectory := false
	if config.InputFile != "-" {
		fileInfo, err := os.Stat(config.InputFile)
		if err == nil {
			isDirectory = fileInfo.IsDir()
		}
	}

	if isDirectory {
		processDirectory(config.InputFile, config.TransformerSource)
		return
	}

	// detect if transformer is a .jsonata/.jsonnet file or a string
	var transformerCode string
	var transformerCodeKnownFormat string
	var transformerFilePath string
	if strings.HasSuffix(config.TransformerSource, ".jsonnet") || strings.HasSuffix(config.TransformerSource, ".json") { // assume a spec file
		jdxd.TraceLog("received a spec file")
		inOutProcessorSpec := readInOutProcessorSpec(config.TransformerSource)
		transformDataStreamSource(config.InputFile,
			*inOutProcessorSpec.Jsonata,
			jdxd.JsonDataToString(inOutProcessorSpec.In),
			jdxd.JsonDataToString(inOutProcessorSpec.Out),
			jdxd.JSONATA_TRANSFORMER,
			transformerFilePath)
		return
	} else if !(strings.HasSuffix(config.TransformerSource, ".jsonata") /* hold on this for now  || strings.HasSuffix(transformerSource, ".jsonnet") */) {
		transformerCode = config.TransformerSource
	} else {
		transformerFilePath = config.TransformerSource
		transformerSourceBytes, err := os.ReadFile(config.TransformerSource)
		transformerCodeKnownFormat = strings.ToLower(strings.TrimPrefix(
			filepath.Ext(config.TransformerSource), "."))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not read transformer file: %s\n", config.TransformerSource)
			os.Exit(1)
		}
		transformerCode = strings.TrimSpace(string(transformerSourceBytes))
	}
	jdxd.TraceLog(fmt.Sprintf("Read transformer code: %s\n", transformerCode))

	transformDataStreamSource(
		config.InputFile, transformerCode, config.InputSchema, config.OutputSchema, transformerCodeKnownFormat, transformerFilePath)
}
