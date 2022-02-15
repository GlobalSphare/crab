package parser

//参数错误-用户输入错误
type Error struct {
	Err error
	ErrorType int
}

func (err Error) Error() string {
	return err.Err.Error()
}