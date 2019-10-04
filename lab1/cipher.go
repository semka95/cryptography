package cipher

import (
	"errors"
	"sort"
)

// ErrCipherUniqueChar means a cipher consists of a repeated characters
var ErrCipherUniqueChar = errors.New("the cipher must consist of unique characters")

// TranspositionEncrypt function encrypts a given text using a cipher using transposition cipher method
func TranspositionEncrypt(text, cipher string) (string, error) {
	textRune, cipherRune, table, encryptedTable := initTransposition(text, cipher)

	if !uniqueCipher(cipherRune) {
		return "", ErrCipherUniqueChar
	}

	arrayToTable(textRune, table)

	for i := range cipherRune {
		min := minRuneIndex(cipherRune)
		for j := range table {
			encryptedTable[j][i] = table[j][min]
		}
		cipherRune[min] = 10000
	}

	res := tableToString(encryptedTable, false)

	return res, nil
}

// TranspositionDecrypt function decrypts a given encoded text using a cipher using transposition cipher method
func TranspositionDecrypt(text, cipher string) (string, error) {
	textRune, cipherRune, table, decryptedTable := initTransposition(text, cipher)

	if !uniqueCipher(cipherRune) {
		return "", ErrCipherUniqueChar
	}

	arrayToTable(textRune, table)

	sortedCipher := sortRuneSlice(cipherRune)

	for i, v := range cipherRune {
		ind := runeIndex(sortedCipher, v)
		for j := range table {
			decryptedTable[j][i] = table[j][ind]
		}
	}

	res := tableToString(decryptedTable, true)

	return res, nil
}

// initTransposition function initializes variables for encrypt/decrypt functions
func initTransposition(text, cipher string) (textRune, cipherRune []rune, table, resTable [][]rune) {
	textRune = []rune(text)
	cipherRune = []rune(cipher)

	lenTbl := 0
	if len(textRune)%len(cipherRune) == 0 {
		lenTbl = len(textRune) / len(cipherRune)
	} else {
		lenTbl = 1 + len(textRune)/len(cipherRune)
	}

	table = make([][]rune, lenTbl)
	resTable = make([][]rune, lenTbl)

	for i := range table {
		table[i] = make([]rune, len(cipherRune))
		resTable[i] = make([]rune, len(cipherRune))
	}
	return
}

// arrayToTable function converts array of runes to table of runes
func arrayToTable(textRune []rune, table [][]rune) {
	offset := 0
	for i, r := range table {
		for j := range r {
			if offset == len(textRune) {
				break
			}
			table[i][j] = textRune[offset]
			offset++
		}
	}

}

// tableToString function converts table of runes to string
func tableToString(table [][]rune, skipZero bool) string {
	res := ""
	for i, r := range table {
		for j := range r {
			if table[i][j] == 0 && skipZero {
				continue
			}
			res += string(table[i][j])
		}
	}
	return res
}

// minRuneIndex function finds index of the smallest rune in array of runes
func minRuneIndex(arr []rune) int {
	min := arr[0]
	minInd := 0

	for i, value := range arr {
		if value < min {
			min = value
			minInd = i
		}
	}

	return minInd
}

// runeIndex function finds index of a given rune in array of runes
func runeIndex(arr []rune, r rune) int {
	for i, value := range arr {
		if value == r {
			return i
		}
	}

	return -1
}

// sortRuneSlice function sorts array of runes
func sortRuneSlice(cipherRune []rune) []rune {
	sortedCipher := make([]rune, len(cipherRune))
	copy(sortedCipher, cipherRune)
	sort.Slice(sortedCipher, func(i, j int) bool {
		return sortedCipher[i] < sortedCipher[j]
	})

	return sortedCipher
}

// uniqueCipher function checks if all runes in slice are unique
func uniqueCipher(cipher []rune) bool {
	keys := make(map[rune]bool)
	for _, entry := range cipher {
		if _, value := keys[entry]; value {
			return false
		}
		keys[entry] = true
	}
	return true
}
