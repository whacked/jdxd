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
	"github.com/spf13/cobra"
)

//go:embed schemas/FileToJsonataTransformerMapping.schema.json
var fileToJsonataTransformerMapping embed.FS

const fileToJsonataTransformerEmbedPath = "schemas/FileToJsonataTransformerMapping.schema.json"

//go:embed schemas/FileToValidatedInOutTransformerMapping.schema.json
var fileToValidatedInOutTransformerMapping embed.FS

const fileToValidatedInOutTransformerEmbedPath = "schemas/FileToValidatedInOutTransformerMapping.schema.json"

//go:embed schemas/InXfmOutSpec.schema.json
var InXfmOutSpec embed.FS

const InXfmOutSpecEmbedPath = "schemas/InXfmOutSpec.schema.json"

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
		inputValidator = jdxd.MakeRecordValidatorFromJsonString("input-schema", inputSchema)
	}
	if outputSchema != "" && outputSchema != "null" {
		outputValidator = jdxd.MakeRecordValidatorFromJsonString("output-schema", outputSchema)
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

func main() {

	var transformerSource, inputFile, inputSchema, outputSchema string

	COLORIZED_PROGRAM_NAME := color.HiBlueString(os.Args[0])
	fmt.Println("HELLO", COLORIZED_PROGRAM_NAME)

	var rootCmd = &cobra.Command{

		Use: strings.Join(
			[]string{
				fmt.Sprintf("\n- <data source> | %s %s  # (read from STDIN)", COLORIZED_PROGRAM_NAME, color.CyanString("[transformer]")),
				fmt.Sprintf("\n- %s %s", COLORIZED_PROGRAM_NAME, color.CyanString("[input-data] [transformer]")),
				fmt.Sprintf("\n- %s %s", COLORIZED_PROGRAM_NAME, color.CyanString("[flags]")),
				"\n",
				"\n[input-data]  is the path to the input data file to be processed, or - to read from STDIN, or implied as STDIN",
				"\n[transformer] is the path to the jsonata or jsonnet file to be used for transformation, or the code as a string",
				"\n[flags]       specify arguments explicitly for more complex processing; see help",
			},
			"",
		),
		Short: "App transforms JSONL/XSV files based on transformation code.",
		RunE: func(cmd *cobra.Command, args []string) error {

			if generateShellCompletionsFlag := cmd.Flag("completions"); generateShellCompletionsFlag.Changed {
				targetShell := generateShellCompletionsFlag.Value.String()
				switch targetShell {
				case "bash":
					cmd.Root().GenBashCompletion(os.Stdout)
					return nil
				case "zsh":
					cmd.Root().GenZshCompletion(os.Stdout)
					return nil
				case "fish":
					cmd.Root().GenFishCompletion(os.Stdout, false)
					return nil
				case "powershell":
					cmd.Root().GenPowerShellCompletion(os.Stdout)
					return nil
				default:
					return fmt.Errorf("unsupported shell: %s", targetShell)
				}
			}

			if transformerSourceFlag := cmd.Flag("transformer"); transformerSourceFlag.Changed {
				transformerSource = transformerSourceFlag.Value.String()
			}
			if inputFileFlag := cmd.Flag("input-data"); inputFileFlag.Changed {
				inputFile = inputFileFlag.Value.String()
			}
			if inputSchemaFlag := cmd.Flag("input-schema"); inputSchemaFlag.Changed {
				inputSchema = inputSchemaFlag.Value.String()
			}
			if outputSchemaFlag := cmd.Flag("output-schema"); outputSchemaFlag.Changed {
				outputSchema = outputSchemaFlag.Value.String()
			}

			if len(args) == 0 {
				return fmt.Errorf("need at least a transformer to do anything")
			}

			if len(args) == 2 && jdxd.IsDirectory(args[0]) {
				processDirectory(args[0], args[1])
			}

			if transformerSource == "" && len(args) == 1 {
				transformerSource = args[0]
				inputFile = "-"
			}

			if transformerSource == "" && inputFile == "" {
				if len(args) == 2 {
					transformerSource = args[len(args)-1]
					inputFile = args[0]
				}
			}

			if transformerSource == "" && inputFile == "" {
				return fmt.Errorf("could not parse %d arguments: %v; you need at least a transformer to do anything", len(args), args)
			}

			// detect if transformer is a .jsonata/.jsonnet file or a string
			var transformerCode string
			var transformerCodeKnownFormat string
			var transformerFilePath string
			if strings.HasSuffix(transformerSource, ".jsonnet") || strings.HasSuffix(transformerSource, ".json") { // assume a spec file
				jdxd.TraceLog("received a spec file")
				inOutProcessorSpec := readInOutProcessorSpec(transformerSource)
				transformDataStreamSource(inputFile,
					*inOutProcessorSpec.Jsonata,
					jdxd.JsonDataToString(inOutProcessorSpec.In),
					jdxd.JsonDataToString(inOutProcessorSpec.Out),
					jdxd.JSONATA_TRANSFORMER,
					transformerFilePath)
				return nil
			} else if !(strings.HasSuffix(transformerSource, ".jsonata") /* hold on this for now  || strings.HasSuffix(transformerSource, ".jsonnet") */) {
				transformerCode = transformerSource
			} else {
				transformerFilePath = transformerSource
				transformerSourceBytes, err := os.ReadFile(transformerSource)
				transformerCodeKnownFormat = strings.ToLower(strings.TrimPrefix(
					filepath.Ext(transformerSource), "."))
				if err != nil {
					return fmt.Errorf("could not read transformer file: %s", transformerSource)
				}
				transformerCode = strings.TrimSpace(string(transformerSourceBytes))
			}
			jdxd.TraceLog(fmt.Sprintf("Read transformer code: %s\n", transformerCode))

			transformDataStreamSource(
				inputFile, transformerCode, inputSchema, outputSchema, transformerCodeKnownFormat, transformerFilePath)
			return nil
		},
	}

	rootCmd.Flags().StringVarP(&inputFile, "input-data", "d", "", "Path to the data file to be processed.")
	rootCmd.Flags().StringVarP(&transformerSource, "transformer", "t", "", "Path to the transformer code file.")
	rootCmd.Flags().StringVarP(&transformerSource, "input-schema", "i", "", "Path to the input schema (json/jsonnet).")
	rootCmd.Flags().StringVarP(&transformerSource, "output-schema", "o", "", "Path to the output schema (json/jsonnet).")
	rootCmd.Flags().StringVarP(&transformerSource, "completions", "", "", "generate shell completions for the specified shell.")

	jdxd.SetDebugLevelFromEnvironment()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
