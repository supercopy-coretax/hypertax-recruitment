package models

type ErrorResponse struct {
	Reason string `json:"reason"`
}

func NewErrorResponse(message string) ErrorResponse {
	return ErrorResponse{
		Reason: message,
	}
}
