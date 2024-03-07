package main

import (
	"context"
	"github.com/jacksonbarreto/WebGateScanner-DNSSECAnalyzer/config"
	"github.com/jacksonbarreto/WebGateScanner-DNSSECAnalyzer/internal/groupHandler"
	"github.com/jacksonbarreto/WebGateScanner-DNSSECAnalyzer/internal/scanner"
	"github.com/jacksonbarreto/WebGateScanner-kafka/consumer"
	"github.com/jacksonbarreto/WebGateScanner-kafka/producer"
)

const configFilePath = ""

func main() {
	config.InitConfig(configFilePath)
	dnsScanner := scanner.NewScannerDefault()

	kafkaProducer, producerErr := producer.NewProducer(config.Kafka().TopicsProducer[0], config.Kafka().Brokers,
		config.Kafka().MaxRetry)
	if producerErr != nil {
		panic(producerErr)
	}
	defer kafkaProducer.Close()

	handler := groupHandler.NewAnalysisConsumerGroupHandlerDefault(dnsScanner, kafkaProducer)

	kafkaConfig := config.Kafka()
	kafkaConsumer, consumerErr := consumer.NewConsumer(kafkaConfig.Brokers, kafkaConfig.GroupID,
		kafkaConfig.TopicsConsumer, handler, context.Background())
	if consumerErr != nil {
		panic(consumerErr)
	}

	consumeErr := kafkaConsumer.Consume()
	if consumeErr != nil {
		panic(consumeErr)
	}
}
