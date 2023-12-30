package main

import (
	"github.com/jacksonbarreto/DNSSECAnalyzer/config"
	"github.com/jacksonbarreto/DNSSECAnalyzer/internal/consumer"
	"github.com/jacksonbarreto/DNSSECAnalyzer/internal/producer"
	"github.com/jacksonbarreto/DNSSECAnalyzer/internal/scanner"
	"log"
)

const configFilePath = ""

func main() {
	config.InitConfig(configFilePath)
	dnsScanner := scanner.NewScannerDefault()

	result, err := dnsScanner.Scan("www.ipb.pt")
	if err != nil {
		log.Printf("Scan failed")
	}
	log.Print(result)

	kafkaProducer, producerErr := producer.NewProducerDefault()
	if producerErr != nil {
		panic(producerErr)
	}
	handler := consumer.NewAnalysisConsumerGroupHandlerDefault(dnsScanner, kafkaProducer)

	kafkaConsumer, consumerErr := consumer.NewConsumerDefault(handler)
	if consumerErr != nil {
		panic(consumerErr)
	}

	consumeErr := kafkaConsumer.Consume()
	if consumeErr != nil {
		panic(consumeErr)
	}
}
