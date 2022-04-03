package did

import (
	"fmt"
	"github.com/pkg/errors"
	didstorage "github.com/tbd54566975/ssi-service/pkg/service/did/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"log"
)

type Method string

const (
	KeyMethod Method = "key"
)

type Service struct {
	// supported DID methods
	handlers map[Method]MethodHandler
	storage  didstorage.Storage
	log      *log.Logger
}

func (s Service) Type() framework.Type {
	return framework.DID
}

// Status is a self-reporting status for the DID service.
func (s Service) Status() framework.Status {
	if s.storage == nil || len(s.handlers) == 0 {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "storage not loaded and/or no DID methods loaded",
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) GetSupportedMethods() []Method {
	var methods []Method
	for method := range s.handlers {
		methods = append(methods, method)
	}
	return methods
}

func (s Service) GetHandler(method Method) (MethodHandler, error) {
	handler, ok := s.handlers[method]
	if !ok {
		return nil, fmt.Errorf("could not get handler for DID method: %s", method)
	}
	return handler, nil
}

// MethodHandler describes the functionality of *all* possible DID service, regardless of method
type MethodHandler interface {
	CreateDID(request CreateDIDRequest) (*CreateDIDResponse, error)
	GetDID(id string) (*GetDIDResponse, error)
}

func NewDIDService(log *log.Logger, methods []Method, s storage.ServiceStorage) (*Service, error) {
	didStorage, err := didstorage.NewDIDStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate DID storage for DID service")
	}
	svc := Service{storage: didStorage, handlers: make(map[Method]MethodHandler)}

	// instantiate all handlers for DID methods
	for _, m := range methods {
		if err := svc.instantiateHandlerForMethod(m); err != nil {
			return nil, errors.Wrap(err, "could not instantiate DID svc")
		}
	}
	return &svc, nil
}

func (s *Service) instantiateHandlerForMethod(method Method) error {
	switch method {
	case KeyMethod:
		handler, err := NewKeyDIDHandler(s.storage)
		if err != nil {
			return fmt.Errorf("could not instnatiate did:%s handler", KeyMethod)
		}
		s.handlers[method] = handler
	default:
		return fmt.Errorf("unsupported DID method: %s", method)
	}
	return nil
}