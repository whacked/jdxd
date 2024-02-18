package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"bufio"

	"github.com/blues/jsonata-go"
	"github.com/fatih/color"
	"github.com/google/go-jsonnet"
	"github.com/spf13/cobra"

	"encoding/csv"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const INPUT_VARIABLE = "in"

var DEBUG_LEVEL = 0

func SetDebugLevelFromEnvironment() {
	maybeDebugEnvVar := os.Getenv("DEBUG")
	if maybeDebugEnvVar != "" {
		if debugLevel, err := strconv.Atoi(maybeDebugEnvVar); err == nil {
			DEBUG_LEVEL = debugLevel
		}
	}
}

func bailOnError(err error) {
	if err != nil {
		ErrorLog(color.RedString(fmt.Sprintf("BAIL: %v", err)))
		os.Exit(1)
	}
}

func DebugLog(msg string) {
	if DEBUG_LEVEL > 0 {
		fmt.Fprintf(os.Stderr, "[INFO] %s\n", msg)
	}
}

func TraceLog(msg string) {
	if DEBUG_LEVEL > 1 {
		fmt.Fprintf(os.Stderr, "[TRACE] %s\n", msg)
	}
}

func ErrorLog(msg string) {
	fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
}

const (
	JSONATA_TRANSFORMER = "jsonata"
	JSONNET_TRANSFORMER = "jsonnet"
)

type TransformationFunc func(interface{}) (interface{}, error)
type JsonTransformer struct {
	Type      string
	Transform TransformationFunc
}

func colorizeByTransformerLanguage(transformerType string, transformerName string) string {
	switch transformerType {
	case JSONATA_TRANSFORMER:
		return color.GreenString(transformerName)
	case JSONNET_TRANSFORMER:
		return color.BlueString(transformerName)
	default:
		return transformerName
	}
}

func wrapDataForTransformation(data interface{}) map[string]interface{} {
	return map[string]interface{}{
		INPUT_VARIABLE: data,
	}
}

func MakeRecordTransformer(transformerCode string, knownCodeFormat string, transformerFilePath string) JsonTransformer {
	// jsonnet compilation seems to fail more easily so try it first

	if knownCodeFormat == "" || knownCodeFormat == JSONNET_TRANSFORMER {

		_, err := jsonnet.SnippetToAST("<transformerCode>", transformerCode)
		if err == nil {
			DebugLog(fmt.Sprintf("Compiled %s expression", colorizeByTransformerLanguage(JSONNET_TRANSFORMER, JSONNET_TRANSFORMER)))
			vm := jsonnet.MakeVM()
			return JsonTransformer{
				Type: JSONNET_TRANSFORMER,
				Transform: func(data interface{}) (interface{}, error) {
					dataAsJson, err := json.Marshal(data)
					if err != nil {
						return nil, err
					}
					vm.ExtCode(INPUT_VARIABLE, string(dataAsJson))

					if transformerFilePath == "" {
						transformerFilePath = "<transformerCode>"
					}
					jsonStr, err := vm.EvaluateAnonymousSnippet(transformerFilePath, transformerCode)
					if err != nil {
						return nil, err
					}
					var outData interface{}
					if err := json.Unmarshal([]byte(jsonStr), &outData); err != nil {
						return nil, err
					}
					return outData, nil
				},
			}
		}
	}

	if knownCodeFormat == "" || knownCodeFormat == JSONATA_TRANSFORMER {
		jsonataEvaluator, err := jsonata.Compile(transformerCode)
		if err == nil {
			DebugLog(fmt.Sprintf("Compiled %s expression", colorizeByTransformerLanguage(JSONATA_TRANSFORMER, JSONATA_TRANSFORMER)))
			return JsonTransformer{
				Type: JSONATA_TRANSFORMER,
				Transform: func(data interface{}) (interface{}, error) {
					res, err := jsonataEvaluator.Eval(wrapDataForTransformation(data))
					if err != nil {
						return nil, err
					}
					return res, nil
				},
			}
		}
	}

	return JsonTransformer{}
}

type JsonDataValidatorFunc func(interface{}) error

func MakeRecordValidatorFromJsonString(name string, jsonSchemaString string) JsonDataValidatorFunc {
	validator, err := jsonschema.CompileString(name, jsonSchemaString)
	if err != nil {
		log.Fatalf("%#v", err)
	}

	return func(inputData interface{}) error {
		if err = validator.Validate(inputData); err != nil {
			return err
		}
		return nil
	}
}

func processJSONLine(line string) interface{} {
	var data interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		return nil
	}
	return data
}

func makeProcessXSVLineFunc(headers []string, delimiter rune) func(string) interface{} {
	return func(line string) interface{} {
		reader := csv.NewReader(strings.NewReader(line))
		reader.Comma = delimiter
		record, err := reader.Read()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading XSV line: %v\n", err)
			return nil
		}
		data := map[string]string{}
		for i, header := range headers {
			if i < len(record) {
				data[header] = record[i]
			}
		}
		return data
	}
}

func detectDelimiter(line string) rune {
	if strings.Contains(line, ",") {
		return ','
	} else if strings.Contains(line, "\t") {
		return '\t'
	}
	return 0 // No valid delimiter found
}

func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	bailOnError(err)
	return fileInfo.IsDir()
}

func transformRecord(
	recordPtr *interface{},
	inputValidator JsonDataValidatorFunc,
	outputValidator JsonDataValidatorFunc,
	recordTransformer JsonTransformer,
) interface{} {
	record := *recordPtr
	if inputValidator != nil {
		err := inputValidator(record)
		if err != nil {
			ErrorLog(color.RedString(fmt.Sprintf("Error validating input record: %v", err)))
			return nil
		}
	}

	inputRecordJson, err := json.Marshal(record)
	if err != nil {
		ErrorLog(color.RedString(fmt.Sprintf("Error serializing input record: %v", err)))
		return nil
	}
	TraceLog(color.MagentaString(fmt.Sprintf("< %s", inputRecordJson)))
	transformedRecord, err := recordTransformer.Transform(record)
	if err != nil {
		ErrorLog(color.RedString(fmt.Sprintf("Error transforming record: %v", err)))
		return nil
	}

	if outputValidator != nil {
		err := outputValidator(transformedRecord)
		if err != nil {
			ErrorLog(color.RedString(fmt.Sprintf("Error validating output record: %v", err)))
			return nil
		}
	}

	return transformedRecord
}

func transformDataStream(
	scanner *bufio.Scanner,
	inputValidator JsonDataValidatorFunc,
	outputValidator JsonDataValidatorFunc,
	recordTransformer JsonTransformer,
) {

	var lineProcessor func(string) interface{}
	linesBuffer := make([]string, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if lineProcessor == nil {
			// Detect format and initialize processing function
			if (strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}")) || (strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")) {
				// jsonl: record per line
				TraceLog("parsing as json lines")
				lineProcessor = processJSONLine
			} else if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") {
				// json: single record
				TraceLog("parsing single JSON record")
				linesBuffer = append(linesBuffer, line)
				break
			} else {
				// Assume XSV and detect delimiter
				TraceLog("parsing as XSV")
				delimiter := detectDelimiter(line)
				if delimiter == 0 {
					ErrorLog(color.RedString(fmt.Sprintf("BAIL: No valid delimiter detected from %s", line)))
					return
				}
				reader := csv.NewReader(strings.NewReader(line))
				reader.Comma = delimiter
				headers, err := reader.Read()
				if err != nil {
					ErrorLog(color.RedString(fmt.Sprintf("Error reading headers: %v", err)))
					return
				}
				lineProcessor = makeProcessXSVLineFunc(headers, delimiter)
				continue // Skip the header for XSV processing
			}
		}

		record := lineProcessor(line)

		if record == nil {
			ErrorLog(color.RedString(fmt.Sprintf("Error processing record: %v", line)))
			return
		}

		transformed := transformRecord(&record, inputValidator, outputValidator, recordTransformer)
		fmt.Println(jsonDataToString(transformed))
	}

	if len(linesBuffer) > 0 {
		for scanner.Scan() {
			linesBuffer = append(linesBuffer, strings.TrimSpace(scanner.Text()))
		}
		record := processJSONLine(strings.Join(linesBuffer, "\n"))
		transformed := transformRecord(&record, inputValidator, outputValidator, recordTransformer)
		fmt.Println(jsonDataToString(transformed))
	}

	if err := scanner.Err(); err != nil {
		ErrorLog(color.RedString(fmt.Sprintf("Error reading from input: %v", err)))
	}
}

func transformFile(
	filePath string,
	inputValidator JsonDataValidatorFunc,
	outputValidator JsonDataValidatorFunc,
	recordTransformer JsonTransformer,
) {

	switch filepath.Ext(filePath) {
	case ".jsonl":
		dataFile, err := os.Open(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening data file: %v\n", err)
			return
		}
		defer dataFile.Close()
		var scanner *bufio.Scanner
		scanner = bufio.NewScanner(dataFile)
		transformDataStream(scanner, inputValidator, outputValidator, recordTransformer)
	case ".json":
		// read the entire file and process it as a single record
		jsonBytes, err := os.ReadFile(filePath)
		bailOnError(err)
		record := processJSONLine(string(jsonBytes))
		transformRecord(&record, inputValidator, outputValidator, recordTransformer)
	}

}

func transformDataStreamSource(
	dataSource string, transformCode string,
	inputSchema string, outputSchema string,
	transformCodeKnownFormat string,
	transformerFilePath string,
) {
	recordTransformer := MakeRecordTransformer(transformCode, transformCodeKnownFormat, transformerFilePath)
	if recordTransformer.Transform == nil {
		fmt.Fprintf(os.Stderr, "Failed to compile transformer code: %s\n", transformCode)
		return
	}

	DebugLog(color.CyanString(fmt.Sprintf("Transforming data source: %s with transform: %s", dataSource, colorizeByTransformerLanguage(recordTransformer.Type, transformCode))))

	var inputValidator JsonDataValidatorFunc
	var outputValidator JsonDataValidatorFunc
	if inputSchema != "" && inputSchema != "null" {
		inputValidator = MakeRecordValidatorFromJsonString("input-schema", inputSchema)
	}
	if outputSchema != "" && outputSchema != "null" {
		outputValidator = MakeRecordValidatorFromJsonString("output-schema", outputSchema)
	}

	if dataSource == "-" {
		transformDataStream(bufio.NewScanner(os.Stdin), inputValidator, outputValidator, recordTransformer)
	} else if isDirectory(dataSource) {
		for _, filePath := range getJsonRecordFiles(dataSource) {
			transformFile(filePath, inputValidator, outputValidator, recordTransformer)
		}
	} else {
		transformFile(dataSource, inputValidator, outputValidator, recordTransformer)
	}
}

func main() {

	var transformerSource, inputFile, inputSchema, outputSchema string

	COLORIZED_PROGRAM_NAME := color.HiBlueString(os.Args[0])

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

			if len(args) == 2 && isDirectory(args[0]) {
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
				TraceLog("received a spec file")
				inOutProcessorSpec := readInOutProcessorSpec(transformerSource)
				transformDataStreamSource(inputFile,
					*inOutProcessorSpec.Jsonata,
					jsonDataToString(inOutProcessorSpec.In),
					jsonDataToString(inOutProcessorSpec.Out),
					JSONATA_TRANSFORMER,
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
				fmt.Printf("Read transformer code: %s\n", transformerCode)
			}

			transformDataStreamSource(inputFile, transformerCode, inputSchema, outputSchema, transformerCodeKnownFormat, transformerFilePath)
			return nil
		},
	}

	rootCmd.Flags().StringVarP(&inputFile, "input-data", "d", "", "Path to the data file to be processed.")
	rootCmd.Flags().StringVarP(&transformerSource, "transformer", "t", "", "Path to the transformer code file.")
	rootCmd.Flags().StringVarP(&transformerSource, "input-schema", "i", "", "Path to the input schema (json/jsonnet).")
	rootCmd.Flags().StringVarP(&transformerSource, "output-schema", "o", "", "Path to the output schema (json/jsonnet).")
	rootCmd.Flags().StringVarP(&transformerSource, "completions", "", "", "generate shell completions for the specified shell.")

	SetDebugLevelFromEnvironment()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
