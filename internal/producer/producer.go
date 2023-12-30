package producer

import (
	"github.com/IBM/sarama"
	"log"
)

type Producer struct {
	syncProducer sarama.SyncProducer
}

func NewProducer(brokers []string) (*Producer, error) {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5

	syncProducer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		log.Printf("Failed to create Kafka producer: %v", err)
		return nil, err
	}

	return &Producer{syncProducer: syncProducer}, nil
}

func (p *Producer) SendMessage(topic string, message string) (partition int32, offset int64, err error) {
	msg := &sarama.ProducerMessage{
		Topic: topic,
		Value: sarama.StringEncoder(message),
	}

	partition, offset, err = p.syncProducer.SendMessage(msg)
	if err != nil {
		log.Printf("Failed to send message: %v", err)
		return 0, 0, err
	}

	return partition, offset, nil
}

func (p *Producer) Close() error {
	if err := p.syncProducer.Close(); err != nil {
		log.Printf("Failed to close Kafka producer: %v", err)
		return err
	}
	return nil
}
