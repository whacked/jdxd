package jdxd

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"bufio"

	"github.com/blues/jsonata-go"
	"github.com/fatih/color"
	"github.com/google/go-jsonnet"

	"encoding/csv"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const INPUT_VARIABLE = "in"

var DEBUG_LEVEL = 0

func SetDebugLevelFromEnvironment() {
	if level := os.Getenv("DEBUG_LEVEL"); level != "" {
		if debugLevel, err := strconv.Atoi(level); err == nil {
			DEBUG_LEVEL = debugLevel
			return
		}
	}
	if level := os.Getenv("DEBUG"); level != "" {
		if debugLevel, err := strconv.Atoi(level); err == nil {
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

func ColorizeByTransformerLanguage(transformerType string, transformerName string) string {
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
			DebugLog(fmt.Sprintf("Compiled %s expression", ColorizeByTransformerLanguage(JSONNET_TRANSFORMER, JSONNET_TRANSFORMER)))
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
			DebugLog(fmt.Sprintf("Compiled %s expression", ColorizeByTransformerLanguage(JSONATA_TRANSFORMER, JSONATA_TRANSFORMER)))
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

func LoadValidator(resourceVariable embed.FS, filePath string) *jsonschema.Schema {
	validatorSource, err := fs.ReadFile(resourceVariable, filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", filePath, err)
	}
	validator, err := jsonschema.CompileString(filePath, string(validatorSource))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling %s: %v\n", filePath, err)
	}
	return validator
}

func RenderJsonnetFile(sourceFile string) string {
	vm := jsonnet.MakeVM()
	jsonStr, err := vm.EvaluateFile(sourceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error evaluating %s: %v\n", sourceFile, err)
	}
	return jsonStr
}

func RenderJsonnetStringOrFile(sourceOrFile string) string {
	if strings.HasSuffix(sourceOrFile, ".jsonnet") {
		return RenderJsonnetFile(sourceOrFile)
	}
	return sourceOrFile
}

func JsonDataToLine(jsonData interface{}) string {
	jsonified, err := json.Marshal(jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
	}
	return string(jsonified)
}

func JsonDataToString(jsonData interface{}) string {
	jsonified, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
	}
	return string(jsonified)
}

func IsDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	bailOnError(err)
	return fileInfo.IsDir()
}

func TransformRecord(
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

func debugShowLineMatchingConditions(line string) {

	TraceLog(fmt.Sprintf("line: %s", line))

	if strings.HasPrefix(line, "{") {
		TraceLog("line starts with {")
	} else {
		TraceLog("line does not start with {")
	}
	if strings.HasSuffix(line, "}") {
		TraceLog("line ends with }")
	} else {
		TraceLog("line does not end with }")
	}
	if strings.HasPrefix(line, "[") {
		TraceLog("line starts with [")
	} else {
		TraceLog("line does not start with [")
	}
	if strings.HasSuffix(line, "]") {
		TraceLog("line ends with ]")
	} else {
		TraceLog("line does not end with ]")
	}
}

func TransformDataStream(
	scanner *bufio.Scanner,
	inputValidator JsonDataValidatorFunc,
	outputValidator JsonDataValidatorFunc,
	recordTransformer JsonTransformer,
) {

	var lineProcessor func(string) interface{}
	linesBuffer := make([]string, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines regardless of processor state
		if line == "" {
			continue
		}

		if lineProcessor == nil {
			debugShowLineMatchingConditions(line)

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

		transformed := TransformRecord(&record, inputValidator, outputValidator, recordTransformer)
		fmt.Println(JsonDataToLine(transformed))
	}

	if len(linesBuffer) > 0 {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				linesBuffer = append(linesBuffer, line)
			}
		}
		record := processJSONLine(strings.Join(linesBuffer, "\n"))
		transformed := TransformRecord(&record, inputValidator, outputValidator, recordTransformer)
		fmt.Println(JsonDataToString(transformed))
	}

	if err := scanner.Err(); err != nil {
		ErrorLog(color.RedString(fmt.Sprintf("Error reading from input: %v", err)))
	}
}

func TransformFile(
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
		TransformDataStream(scanner, inputValidator, outputValidator, recordTransformer)
	case ".json":
		// read the entire file and process it as a single record
		jsonBytes, err := os.ReadFile(filePath)
		bailOnError(err)
		record := processJSONLine(string(jsonBytes))
		transformed := TransformRecord(&record, inputValidator, outputValidator, recordTransformer)
		fmt.Println(JsonDataToString(transformed))
	}

}
