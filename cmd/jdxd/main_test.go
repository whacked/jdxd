// It tests the CLI argument handling for the jdxd command.
package main

import (
	"errors"
	"testing"
	"strings"

	"github.com/stretchr/testify/assert"
)

func TestParseArgs(t *testing.T) {
  // tests argument parser's ability to handle various CLI command combinations
  tests := []struct {
		name           string
		cmdLine        string
		expectedConfig *JDXDCliConfig
		wantErr        bool
	}{
		{
			name:    "no arguments",
			cmdLine: ProgramName,
			wantErr: true,
		},
		{
			name:    "single transformer arg (stdin mode)",
			cmdLine: ProgramName + " transform.jsonata",
			expectedConfig: &JDXDCliConfig{
				TransformerSource: "transform.jsonata",
				InputFile:        "-",
				IsStdin:         true,
			},
		},
		{
			name:    "input data file and transformer args",
			cmdLine: ProgramName + " input.json transform.jsonata",
			expectedConfig: &JDXDCliConfig{
				TransformerSource: "transform.jsonata",
				InputFile:        "input.json",
			},
		},
		{
			name:    "flag-based transformer with stdin",
			cmdLine: ProgramName + " --transformer transform.jsonata",
			expectedConfig: &JDXDCliConfig{
				TransformerSource: "transform.jsonata",
				InputFile:        "-",
				IsStdin:         true,
			},
		},
		{
			name:    "flag-based transformer with stdin explicit",
			cmdLine: ProgramName + " --transformer transform.jsonata --input-data -",
			expectedConfig: &JDXDCliConfig{
				TransformerSource: "transform.jsonata",
				InputFile:        "-",
				IsStdin:         true,
			},
		},
		{
			name:    "flag-based transformer with input file",
			cmdLine: ProgramName + " --transformer transform.jsonata --input-data input.json",
			expectedConfig: &JDXDCliConfig{
				TransformerSource: "transform.jsonata",
				InputFile:        "input.json",
			},
		},
		{
			name:    "flag-based transformer with schemas",
			cmdLine: ProgramName + " --transformer transform.jsonata --input-data input.json --input-schema input.schema.json --output-schema output.schema.json",
			expectedConfig: &JDXDCliConfig{
				TransformerSource: "transform.jsonata",
				InputFile:        "input.json",
				InputSchema:      "input.schema.json",
				OutputSchema:     "output.schema.json",
			},
		},
		{
			name:    "shell completions - bash",
			cmdLine: ProgramName + " --completions bash",
			expectedConfig: &JDXDCliConfig{
				GenerateShellCompletions: "bash",
			},
		},
		{
			name:    "shell completions - zsh",
			cmdLine: ProgramName + " --completions zsh",
			expectedConfig: &JDXDCliConfig{
				GenerateShellCompletions: "zsh",
			},
		},
		{
			name:    "shell completions - fish",
			cmdLine: ProgramName + " --completions fish",
			expectedConfig: &JDXDCliConfig{
				GenerateShellCompletions: "fish",
			},
		},
		{
			name:    "shell completions - powershell",
			cmdLine: ProgramName + " --completions powershell",
			expectedConfig: &JDXDCliConfig{
				GenerateShellCompletions: "powershell",
			},
		},
		{
			name:    "invalid flag combination - both positional and flag transformer",
			cmdLine: ProgramName + " transform.jsonata --transformer other.jsonnet",
			wantErr: true,
		},
		{
			name:    "invalid flag combination - both positional and flag input",
			cmdLine: ProgramName + " input.json transform.jsonata --input-data other.json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := strings.Fields(tt.cmdLine)
			config, err := parseArgs(args[1:])

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedConfig, config)
			}
		})
	}
}

// TestJDXDCliConfigValidation tests the validation rules for JDXDCliConfig
func TestJDXDCliConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *JDXDCliConfig
		wantErr bool
		wantField  string
		wantReason string
	}{
		{
			name: "valid shell completion",
			config: &JDXDCliConfig{
				GenerateShellCompletions: "bash",
			},
		},
		{
			name: "invalid shell completion",
			config: &JDXDCliConfig{
				GenerateShellCompletions: "invalid",
			},
			wantErr: true,
			wantField:  "GenerateShellCompletions",
			wantReason: "unsupported shell",
		},
		{
			name: "nonexistent transformer",
			config: &JDXDCliConfig{
				TransformerSource: "nonexistent.jsonata",
				InputFile:        "-",
				IsStdin:         true,
			},
			wantErr: true,
			wantField:  "TransformerSource",
			wantReason: "file not found",
		},
		{
			name: "invalid stdin mode",
			config: &JDXDCliConfig{
				TransformerSource: "transform.does-not-exist.fake",
				InputFile:        "not-stdin",
			},
			wantErr: true,
			wantField:  "TransformerSource",
			wantReason: "file not found",
		},

		/*
		{
			name: "transformer with input file",
			config: &JDXDCliConfig{
				TransformerSource: "$.in",
				InputFile:        "schemas/FileToJsonataTransformerMapping.schema.json",
			},
			wantErr: false,
		},
		*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.IsValid()
		
			if tt.wantErr {
				assert.Error(t, err)
		
				var verr ConfigValidationError
				if errors.As(err, &verr) {
					if tt.wantField != "" {
						assert.Equal(t, tt.wantField, verr.Field, "field mismatch")
					}
					if tt.wantReason != "" {
						assert.Equal(t, tt.wantReason, verr.Reason, "reason mismatch")
					}
				} else {
					t.Fatalf("expected ConfigValidationError, got: %T", err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

