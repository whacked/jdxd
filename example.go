package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/blues/jsonata-go"
	"github.com/google/go-jsonnet"
)

func removeCStyleComments(input string) string {
	re := regexp.MustCompile(`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/`)
	return re.ReplaceAllString(input, "")
}

func readTransformerSource(sourceFile string) map[string]*jsonata.Expr {

	vm := jsonnet.MakeVM()

	jsonStr, err := vm.EvaluateFile(sourceFile)
	if err != nil {
		DebugLog(fmt.Sprintf("FAILED TO EVALUATE JSONNET FROM %s", sourceFile))
		panic(err)
	}

	var fileMatchersToJsonata map[string]string

	if err := json.Unmarshal([]byte(jsonStr), &fileMatchersToJsonata); err != nil {
		DebugLog(fmt.Sprintf("FAILED TO UNMARSHAL JSON FROM %s", sourceFile))
		panic(err)
	}

	var out map[string]*jsonata.Expr = make(map[string]*jsonata.Expr)
	for pattern, transformerCode := range fileMatchersToJsonata {
		if transformerCode == "" {
			continue
		}
		cleanedCode := removeCStyleComments(transformerCode)
		out[pattern] = jsonata.MustCompile(cleanedCode)
	}
	return out
}

func GetJSONataTransformer(TransformerMap map[string]*jsonata.Expr, filePath string) *jsonata.Expr {
	for pattern, transformer := range TransformerMap {
		matched, _ := regexp.MatchString(pattern, filePath)
		if matched {
			return transformer
		}
	}
	return nil
}

func ApplyJSONataTransformer(transformer *jsonata.Expr, jsonData interface{}) interface{} {

	wrappedData := map[string]interface{}{INPUT_VARIABLE: jsonData}
	res, err := transformer.Eval(wrappedData)
	if err != nil {
		DebugLog(fmt.Sprintf("failed to eval:\n%v\nusing\n%v", wrappedData, transformer))
		panic(err)
	}
	return res
}

func main() {
	SetDebugLevelFromEnvironment()

	/*
		globs into a data directory for json files
		then using the spec file that contains <file-name-match-pattern>:<jsonata-transformer>
		it applies the transformer to each of the matched files
	*/

	if len(os.Args) != 3 {
		fmt.Println("Usage: example <spec-file> <data-dir>")
		os.Exit(1)
	}

	specFile := os.Args[1]
	dataDir := os.Args[2]

	filePattern := "**/*.json"

	matches, err := filepath.Glob(filepath.Join(dataDir, filePattern))
	if err != nil {
		DebugLog(fmt.Sprintf("Error: %v", err))
		os.Exit(1)
	}

	transformerMap := readTransformerSource(specFile)

	DebugLog(fmt.Sprintf("Found %d files in %s", len(matches), dataDir))

	numProcessed := 0
	for _, filePath := range matches {

		transformer := GetJSONataTransformer(transformerMap, filePath)
		if transformer == nil {
			DebugLog(fmt.Sprintf("No transformer found for file: %s", filePath))
			continue
		}

		DebugLog(fmt.Sprintf("Processing file: %s", filePath))
		DebugLog(fmt.Sprintf("Transformer code: %s", transformer))

		jsonContent, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading file: %v", err)
			continue
		}

		var jsonData interface{}
		err = json.Unmarshal(jsonContent, &jsonData)
		if err != nil {
			DebugLog(fmt.Sprintf("Error unmarshaling JSON: %v", err))
			continue
		}
		result := ApplyJSONataTransformer(transformer, jsonData)

		jsonified, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			DebugLog(fmt.Sprintf("Error marshaling JSON: %v", err))
			break
		}
		fmt.Fprintf(os.Stdout, "%s", jsonified)
		numProcessed++
	}

	DebugLog(fmt.Sprintf("Processed %d files", numProcessed))
}
