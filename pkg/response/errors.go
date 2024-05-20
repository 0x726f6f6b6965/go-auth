package response

const (
	SuccessCode                    = 200
	ErrorCode                      = -1
	ErrorCodeOfInternalServerError = 500 // internal server error, please check server log
	ErrorCodeOfInvalidParams       = 400 // param error
)

var (
	Success             = ErrorString{SuccessCode, "success"}
	InvalidParamErr     = ErrorString{ErrorCodeOfInvalidParams, "Wrong request parameter"}
	InternalServerError = ErrorString{ErrorCodeOfInternalServerError, "Service internal exception"}
)

type ErrorString struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
