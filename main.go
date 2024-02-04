package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
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

func MakeRecordTransformer(transformerCode string) JsonTransformer {
	// jsonnet compilation seems to fail more easily so try it first

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
				jsonStr, err := vm.EvaluateAnonymousSnippet("<transformerCode>", transformerCode)
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

	return JsonTransformer{}
}

type JsonDataValidatorFunc func(interface{}) error

func MakeRecordValidator(name string, jsonSchemaString string) JsonDataValidatorFunc {
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

func transformDataStream(
	dataSource string, transformCode string,
	inputSchema string, outputSchema string,
) {
	recordTransformer := MakeRecordTransformer(transformCode)
	if recordTransformer.Transform == nil {
		fmt.Fprintf(os.Stderr, "Failed to compile transformer code: %s\n", transformCode)
		return
	}

	DebugLog(color.CyanString(fmt.Sprintf("Transforming data source: %s with transform: %s", dataSource, colorizeByTransformerLanguage(recordTransformer.Type, transformCode))))

	var inputValidator JsonDataValidatorFunc
	var outputValidator JsonDataValidatorFunc
	if inputSchema != "" {
		inputValidator = MakeRecordValidator("input-schema", inputSchema)
	}
	if outputSchema != "" {
		outputValidator = MakeRecordValidator("output-schema", outputSchema)
	}

	var scanner *bufio.Scanner
	if dataSource != "-" {
		dataFile, err := os.Open(dataSource)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening data file: %v\n", err)
			return
		}
		defer dataFile.Close()
		scanner = bufio.NewScanner(dataFile)

	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	var lineProcessor func(string) interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if lineProcessor == nil {
			// Detect format and initialize processing function
			if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") {
				lineProcessor = processJSONLine
			} else {
				// Assume XSV and detect delimiter
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
			continue
		}

		if inputValidator != nil {
			err := inputValidator(record)
			if err != nil {
				ErrorLog(color.RedString(fmt.Sprintf("Error validating input record: %v", err)))
				continue
			}
		}

		inputRecordJson, err := json.Marshal(record)
		if err != nil {
			ErrorLog(color.RedString(fmt.Sprintf("Error serializing input record: %v", err)))
			continue
		}
		TraceLog(color.MagentaString(fmt.Sprintf("< %s", inputRecordJson)))
		transformedRecord, err := recordTransformer.Transform(record)
		if err != nil {
			ErrorLog(color.RedString(fmt.Sprintf("Error transforming record: %v", err)))
			continue
		}
		transformedRecordJson, err := json.Marshal(transformedRecord)
		if err != nil {
			ErrorLog(color.RedString(fmt.Sprintf("Error serializing transformed record: %v", err)))
			continue
		}

		if outputValidator != nil {
			err := outputValidator(transformedRecord)
			if err != nil {
				ErrorLog(color.RedString(fmt.Sprintf("Error validating output record: %v", err)))
				continue
			}
		}

		fmt.Println(string(transformedRecordJson))
	}

	if err := scanner.Err(); err != nil {
		ErrorLog(color.RedString(fmt.Sprintf("Error reading from input: %v", err)))
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

			if len(args) == 0 {
				return fmt.Errorf("need at least a transformer to do anything")
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
			if !(strings.HasSuffix(transformerSource, ".jsonata") || strings.HasSuffix(transformerSource, ".jsonnet")) {
				transformerCode = transformerSource
			} else {
				transformerFile, err := os.Open(transformerSource)
				if err != nil {
					return fmt.Errorf("could not open transformer file: %s", transformerSource)
				}
				defer transformerFile.Close()
				transformerReader := bufio.NewReader(transformerFile)
				transformerCode, err = transformerReader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("could not read transformer file: %s", transformerSource)
				}
				transformerCode = strings.TrimSpace(transformerCode)
				fmt.Printf("Read transformer code: %s\n", transformerCode)
			}

			transformDataStream(inputFile, transformerCode, inputSchema, outputSchema)
			return nil
		},
	}

	rootCmd.Flags().StringVarP(&inputFile, "input-data", "d", "", "Path to the data file to be processed.")
	rootCmd.Flags().StringVarP(&transformerSource, "transformer", "t", "", "Path to the transformer code file.")
	rootCmd.Flags().StringVarP(&transformerSource, "input-schema", "i", "", "Path to the input schema (json/jsonnet).")
	rootCmd.Flags().StringVarP(&transformerSource, "output-schema", "o", "", "Path to the output schema (json/jsonnet).")
	rootCmd.Flags().StringVarP(&transformerSource, "completions", "", "", "generate shell completions for the specified shell.")

	maybeDebugEnvVar := os.Getenv("DEBUG")
	if maybeDebugEnvVar != "" {
		if debugLevel, err := strconv.Atoi(maybeDebugEnvVar); err == nil {
			DEBUG_LEVEL = debugLevel
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
