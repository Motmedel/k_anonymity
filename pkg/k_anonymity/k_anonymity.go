package k_anonymity

import (
	"bufio"
	"context"
	"fmt"
	kAnonymityErrors "github.com/Motmedel/k_anonymity/pkg/errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"golang.org/x/sync/errgroup"
	"hash"
	"io"
	"sync"
)

func generateHash(input []byte, hashFactory func() hash.Hash, salt []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	if hashFactory == nil {
		return nil, motmedelErrors.NewWithTrace(kAnonymityErrors.ErrNilHashFactory)
	}

	hasher := hashFactory()
	hasher.Write(salt)
	hasher.Write(input)

	return hasher.Sum(nil), nil
}

func GenerateMap(
	reader io.Reader,
	hashFactory func() hash.Hash,
	prefixLength int,
	salt []byte,
) (map[string][]string, error) {
	if reader == nil {
		return nil, nil
	}

	if hashFactory == nil {
		return nil, motmedelErrors.NewWithTrace(kAnonymityErrors.ErrNilHashFactory)
	}

	if prefixLength <= 0 {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("%w: %d", kAnonymityErrors.ErrBadPrefixLength, prefixLength),
		)
	}

	hashPrefixToHashes := make(map[string][]string)

	errGroup, _ := errgroup.WithContext(context.Background())
	var mapLock sync.Mutex

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		input := scanner.Text()
		if input == "" {
			continue
		}

		errGroup.Go(
			func() error {
				hashInput := []byte(input)
				inputHash, err := generateHash(hashInput, hashFactory, salt)
				if err != nil {
					return motmedelErrors.New(fmt.Errorf("generate hash: %w", err), hashInput)
				}

				if prefixLength > len(inputHash) {
					return motmedelErrors.NewWithTrace(
						fmt.Errorf(
							"%w: %w: %d",
							kAnonymityErrors.ErrBadPrefixLength,
							kAnonymityErrors.ErrTooLargePrefix,
							prefixLength,
						),
					)
				}

				hashPrefix := string(inputHash[:prefixLength])
				mapLock.Lock()
				defer mapLock.Unlock()
				hashPrefixToHashes[hashPrefix] = append(hashPrefixToHashes[hashPrefix], fmt.Sprintf("%x", inputHash))

				return nil
			},
		)
	}

	if err := scanner.Err(); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("scanner: %w", err))
	}

	if err := errGroup.Wait(); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("errgroup wait: %w", err))
	}

	return hashPrefixToHashes, nil
}
