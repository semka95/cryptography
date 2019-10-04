package cipher

import "testing"

func TestTranspositionEncrypt(t *testing.T) {
	text := "перестановочный шифр12"
	cipher := "шифр"

	got, err := TranspositionEncrypt(text, cipher)

	if err != nil {
		t.Fatal("should not got error:", err)
	}

	want := "еерптнасвчооы йнирфш2\x00\x001"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTranspositionDecrypt(t *testing.T) {
	encryptedText := "еерптнасвчооы йнирфш"
	cipher := "шифр"

	got, err := TranspositionDecrypt(encryptedText, cipher)

	assertNoError(t, err)

	want := "перестановочный шифр"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTranspositionEncryptDecrypt(t *testing.T) {
	text := "перестановочный шифр21"
	cipher := "шифр"

	got, err := TranspositionEncrypt(text, cipher)

	assertNoError(t, err)

	got, err = TranspositionDecrypt(got, cipher)

	assertNoError(t, err)

	want := "перестановочный шифр21"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCipherUnique(t *testing.T) {
	t.Run("Encrypt function test", func(t *testing.T) {
		text := "перестановочный шифр"
		cipher := "ши11"

		_, err := TranspositionEncrypt(text, cipher)

		assertError(t, err, ErrCipherUniqueChar)
	})

	t.Run("Decrypt function test", func(t *testing.T) {
		text := "еерптнасвчооы йнирфш"
		cipher := "ши11"

		_, err := TranspositionDecrypt(text, cipher)

		assertError(t, err, ErrCipherUniqueChar)
	})

}

func assertError(t *testing.T, got error, want error) {
	t.Helper()
	if got == nil {
		t.Fatal("didn't get an error but wanted one")
	}

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
func assertNoError(t *testing.T, got error) {
	t.Helper()
	if got != nil {
		t.Fatal("got an error but didn't want one")
	}
}
