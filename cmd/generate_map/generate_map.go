package main

import (
	"crypto/sha256"
	_ "embed"
	"flag"
	"fmt"
	kAnonymityErrors "github.com/Motmedel/k_anonymity/pkg/errors"
	"github.com/Motmedel/k_anonymity/pkg/k_anonymity"
	motmedelUtilsEnv "github.com/Motmedel/utils_go/pkg/env"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	errorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/vphpersson/code_generation_go/pkg/code_generation"
	"log/slog"
	"os"
	"reflect"
	"strings"
)

const codeGeneratedString = "// Code generated by github.com/Motmedel/k_anonymity/cmd/generate_map; DO NOT EDIT.\n"

func main() {
	logger := errorLogger.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger.Logger)

	var inPath string
	flag.StringVar(&inPath, "in", "", "The path of the input file.")

	var prefixLength int
	flag.IntVar(&prefixLength, "prefix-length", 0, "The prefix length.")

	var salt string
	flag.StringVar(&salt, "salt", "", "The salt.")

	var packageName string
	flag.StringVar(
		&packageName,
		"package-name",
		motmedelUtilsEnv.GetEnvWithDefault("GOPACKAGE", "main"),
		"The name of the package in the output.",
	)

	var variableName string
	flag.StringVar(&variableName, "variable", "x", "The name of the variable in the output.")

	flag.Parse()

	if prefixLength <= 0 {
		logger.FatalWithExitingMessage(
			"Bad prefix length.",
			motmedelErrors.NewWithTrace(fmt.Errorf("%w: %d", kAnonymityErrors.ErrBadPrefixLength, prefixLength)),
		)
	}

	var input *os.File
	if inPath == "" {
		input = os.Stdin
	} else {
		var err error
		input, err = os.Open(inPath)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when opening the input file.",
				motmedelErrors.NewWithTrace(fmt.Errorf("os open (input file): %w", err), inPath),
			)
		}
	}

	saltData := []byte(salt)
	hashPrefixToHashes, err := k_anonymity.GenerateMap(input, sha256.New, prefixLength, saltData)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when generating the map.",
			motmedelErrors.New(fmt.Errorf("generate map: %w", err), input, prefixLength, saltData),
		)
	}

	literal, _, err := code_generation.GenerateLiteral(reflect.ValueOf(hashPrefixToHashes), nil)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when generating the map literal.",
			fmt.Errorf("generate literal: %w", err),
		)
	}

	output := fmt.Sprintf("package %s\n\nvar %s = %s", packageName, variableName, literal)

	if gofile := os.Getenv("GOFILE"); gofile != "" {
		fileName := strings.TrimSuffix(gofile, ".go") + "_generated.go"
		data := []byte(codeGeneratedString + output)
		if err := os.WriteFile(fileName, data, 0600); err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when writing the file.",
				motmedelErrors.New(fmt.Errorf("os write file: %w", err), fileName, data),
			)
		}
	} else {
		fmt.Println(output)
	}
}
