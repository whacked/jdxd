package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"embed"

	"github.com/google/go-jsonnet"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schemas/FileToJsonataTransformerMapping.schema.json
var fileToJsonataTransformerMapping embed.FS

//go:embed schemas/FileToValidatedInOutTransformerMapping.schema.json
var fileToValidatedInOutTransformerMapping embed.FS

//go:embed schemas/InXfmOutSpec.schema.json
var InXfmOutSpec embed.FS

func removeCStyleComments(input string) string { // jsonata-go doesn't parse comments now
	re := regexp.MustCompile(`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/`)
	return re.ReplaceAllString(input, "")
}

func loadValidator(resourceVariable embed.FS, filePath string) *jsonschema.Schema {
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

func renderJsonnetFile(sourceFile string) string {
	vm := jsonnet.MakeVM()
	jsonStr, err := vm.EvaluateFile(sourceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error evaluating %s: %v\n", sourceFile, err)
	}
	return jsonStr
}

func jsonDataToString(jsonData interface{}) string {
	jsonified, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
	}
	return string(jsonified)
}

func readInOutProcessorSpec(sourceFile string) *InXfmOutSpecSchemaJson {
	jsonStr := renderJsonnetFile(sourceFile)
	var toValidate interface{} // InXfmOutSpecSchemaJson
	if err := json.Unmarshal([]byte(jsonStr), &toValidate); err != nil {
		fmt.Fprintf(os.Stderr, "Error unmarshaling %s: %v\n", sourceFile, err)
	}
	var out *InXfmOutSpecSchemaJson
	validator := loadValidator(InXfmOutSpec, "schemas/InXfmOutSpec.schema.json")
	if err := validator.Validate(toValidate); err != nil {
		fmt.Fprintf(os.Stderr, "Error validating %s: %v\n", sourceFile, err)
	} else {
		var toValidate InXfmOutSpecSchemaJson
		if err := json.Unmarshal([]byte(jsonStr), &toValidate); err != nil {
			fmt.Fprintf(os.Stderr, "Error unmarshaling %s: %v\n", sourceFile, err)
		}
		if toValidate.Jsonata == nil {
			log.Fatalf("Jsonata is currently required in %s", sourceFile)
		}
		cleanedCode := removeCStyleComments(*toValidate.Jsonata)
		out = &InXfmOutSpecSchemaJson{
			In:      toValidate.In,
			Jsonata: &cleanedCode,
			Out:     toValidate.Out,
		}
	}
	return out
}

func readDirectoryProcessorSpec(sourceFile string) map[string]*InXfmOutSpecSchemaJson {
	jsonStr := renderJsonnetFile(sourceFile)

	var toValidate map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &toValidate); err != nil {
		DebugLog(fmt.Sprintf("1. FAILED TO UNMARSHAL JSON FROM %s", sourceFile))
		panic(err)
	}

	var out map[string]*InXfmOutSpecSchemaJson = make(map[string]*InXfmOutSpecSchemaJson)
	fileToJsonnetTransformerMappingValidator := loadValidator(fileToJsonataTransformerMapping, "schemas/FileToJsonataTransformerMapping.schema.json")

	if err := fileToJsonnetTransformerMappingValidator.Validate(toValidate); err != nil {
		DebugLog(fmt.Sprintf("2. FAILED TO VALIDATE JSON FROM %s", sourceFile))
		fmt.Fprintf(
			os.Stderr,
			"Error validating FileToJsonataTransformerMapping: %v\n",
			err,
		)
	} else {
		DebugLog(fmt.Sprintf("2. VALIDATED JSON FROM %s", sourceFile))
		for pattern, transformerCode := range toValidate {
			if transformerCode == "" {
				out[pattern] = nil
				continue
			}
			out[pattern] = &InXfmOutSpecSchemaJson{}
			cleanedCode := removeCStyleComments(transformerCode.(string))
			out[pattern].Jsonata = &cleanedCode
		}
	}

	fileToValidatedInOutTransformerMappingValidator := loadValidator(fileToValidatedInOutTransformerMapping, "schemas/FileToValidatedInOutTransformerMapping.schema.json")

	if err := fileToValidatedInOutTransformerMappingValidator.Validate(toValidate); err != nil {
		DebugLog(fmt.Sprintf("3. FAILED TO VALIDATE JSON FROM %s", sourceFile))
		fmt.Println(err)
	} else {
		DebugLog(fmt.Sprintf("3. VALIDATED JSON FROM %s", sourceFile))
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
			out[pattern] = &InXfmOutSpecSchemaJson{
				In:      mappedValue["inputSchema"].(map[string]interface{}),
				Jsonata: &cleanedCode,
				Out:     mappedValue["outputSchema"].(map[string]interface{}),
			}

		}
	}

	return out
}

func getTransformerSpec(transformerMap map[string]*InXfmOutSpecSchemaJson, filePath string) *InXfmOutSpecSchemaJson {
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

	DebugLog(fmt.Sprintf("Found %d files in %s", len(matches), rootDirectory))

	numProcessed := 0
	for _, filePath := range matches {

		transformerSpec := getTransformerSpec(transformerMap, filePath)
		if transformerSpec == nil {
			DebugLog(fmt.Sprintf("No transformer found for file: %s", filePath))
			continue
		}

		DebugLog(fmt.Sprintf("Processing file: %s", filePath))
		DebugLog(fmt.Sprintf("Transformer code: %v", transformerSpec))

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

		transformer := MakeRecordTransformer(*transformerSpec.Jsonata, JSONATA_TRANSFORMER, directoryProcessorSpecFile)
		result := transformRecord(&jsonData, nil, nil, transformer)
		jsonified := jsonDataToString(result)

		fmt.Fprintf(os.Stdout, "%s\n", jsonified)
		numProcessed++

		// save to /tmp/transformed.json
		// err = os.WriteFile("/tmp/transformed.json", jsonified, 0644)

		break
	}

	DebugLog(fmt.Sprintf("Processed %d files", numProcessed))
}
