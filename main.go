package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Função faz a leitura de um arquivo e retorna os dados decodificados de base64
func lerArquivoBase64(ciphertext string) ([]byte, error) {
	dadosB64, err := os.ReadFile(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Erro ao ler o arquivo %s: %w", ciphertext, err)
	}

	decodificado, err := base64.StdEncoding.DecodeString(string(dadosB64))
	if err != nil {
		return nil, fmt.Errorf("Erro ao decodificar o conteúdo de %s: %w", ciphertext, err)
	}

	return decodificado, nil
}

// decapSegredo realiza a decapsulação de um segredo compartilhado com Kyber768.
// Recebe o ciphertext e a chave privada como bytes e retorna o segredo compartilhado.
func decapSegredo(ciphertext, privateKey []byte) ([]byte, error) {
	kem := new(oqs.KEM)

	if err := kem.Init("Kyber768", nil); err != nil {
		return nil, fmt.Errorf("erro ao inicializar Kyber768: %w", err)
	}

	defer kem.Clean()

	segredoCompatilhado, err := kem.Decapsulate(ciphertext, privateKey)
	if err != nil {
		return nil, fmt.Errorf("erro ao desencapsular o segredo: %w", err)
	}

	return segredoCompatilhado, nil
}

func main() {
	// Lê e decodifica os arquivos
	ciphertext, err := lerArquivoBase64("ciphertext.b64")
	if err != nil {
		log.Fatal(err)
	}

	chavePrivada, err := lerArquivoBase64("private_key.b64")
	if err != nil {
		log.Fatal(err)
	}

	// Decapsula o segredo compartilhado
	segredoCompatilhado, err := decapSegredo(ciphertext, chavePrivada)
	if err != nil {
		log.Fatal(err)
	}

	// Exibe o segredo em base64
	fmt.Println("Segredo compartilhado (base64):", base64.StdEncoding.EncodeToString(segredoCompatilhado))
}
