package groupHandler

import (
	"encoding/json"
	"github.com/IBM/sarama"
	"github.com/jacksonbarreto/WebGateScanner-DNSSECAnalyzer/config"
	"github.com/jacksonbarreto/WebGateScanner-DNSSECAnalyzer/internal/scanner"
	"github.com/jacksonbarreto/WebGateScanner-DNSSECAnalyzer/pkg/logservice"
	"github.com/jacksonbarreto/WebGateScanner-DNSSECAnalyzer/pkg/models"
	kmodels "github.com/jacksonbarreto/WebGateScanner-kafka/models"
	"github.com/jacksonbarreto/WebGateScanner-kafka/producer"
	"time"
)

type AnalysisConsumerGroupHandler struct {
	scanner     *scanner.Scanner
	producer    producer.IProducer
	topicResult string
	topicError  string
	log         logservice.Logger
}

func NewAnalysisConsumerGroupHandler(scanner *scanner.Scanner, producer producer.IProducer, topicResult, topicError string, logService logservice.Logger) *AnalysisConsumerGroupHandler {
	return &AnalysisConsumerGroupHandler{
		scanner:     scanner,
		producer:    producer,
		topicResult: topicResult,
		topicError:  topicError,
		log:         logService,
	}
}

func NewAnalysisConsumerGroupHandlerDefault(scanner *scanner.Scanner, producer producer.IProducer) *AnalysisConsumerGroupHandler {
	kafkaConfig := config.Kafka()
	topic := kafkaConfig.TopicProducer
	topicError := kafkaConfig.TopicError
	logger := logservice.NewLogServiceDefault()
	return NewAnalysisConsumerGroupHandler(scanner, producer, topic, topicError, logger)
}

func (h *AnalysisConsumerGroupHandler) Setup(session sarama.ConsumerGroupSession) error {
	return nil
}

func (h *AnalysisConsumerGroupHandler) Cleanup(session sarama.ConsumerGroupSession) error {
	return nil
}

func (h *AnalysisConsumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for message := range claim.Messages() {
		h.log.Info("Message claimed: value = %s, timestamp = %v, topic = %s", string(message.Value), message.Timestamp, message.Topic)

		var evalRequest kmodels.EvaluationRequest
		err := json.Unmarshal(message.Value, &evalRequest)
		if err != nil {
			h.log.Error("Error unmarshalling message: %v", err)
			continue
		}
		startTime := time.Now().Unix()
		h.log.Info("Starting evaluation for Institution ID %d with URL %s at timestamp %d", evalRequest.InstitutionID, evalRequest.URL, startTime)

		result, ScanErr := h.scanner.Scan(evalRequest.URL)
		if ScanErr != nil {
			h.handleError(evalRequest.URL, ScanErr)
			continue
		}
		kafkaMessage, msgErr := createKafkaMessage(result, evalRequest.InstitutionID)
		if msgErr != nil {
			h.handleError(evalRequest.URL, ScanErr)
			continue
		}
		partition, offset, producerErr := h.producer.SendMessage(kafkaMessage)
		if producerErr != nil {
			h.handleError(evalRequest.URL, ScanErr)
			continue
		}
		h.log.Info("Message successfully sent to partition %d at offset %d", partition, offset)
		session.MarkMessage(message, "")
	}
	return nil
}

func createKafkaMessage(result *models.Assessment, institutionID string) (string, error) {
	evalResponse := kmodels.EvaluationResponse{
		StartTime:     result.Start.Unix(),
		EndTime:       result.End.Unix(),
		Origin:        config.App().Id,
		InstitutionID: institutionID,
	}

	resultJson, err := json.Marshal(result)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(resultJson, &evalResponse.EvaluationResult)
	if err != nil {
		return "", err
	}

	jsonData, err := json.Marshal(evalResponse)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func (h *AnalysisConsumerGroupHandler) handleError(url string, err error) {
	h.log.Error("Error encountered for URL '%s' in '%s': %v", url, err)
}
